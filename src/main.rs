use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;

struct NameServer {
    address: Ipv4Addr,
    name: Name,
}

/// For now this represents an A record check, but it may become an enum or various
/// check types (perhaps not limited to DNS checks).
struct Check<'a> {
    name_server: &'a NameServer,
    record_to_request: &'a Name,
    expected_ip: &'a Ipv4Addr,
}

const ISSUE_TITLE: &str = "Outage Report";

fn main() {
    let name_servers = get_name_servers();
    let checks = get_checks(&name_servers);
    let checks_with_results: Vec<(Check, Result<(), ()>)> = checks
        .into_iter()
        .map(|check| {
            let result = perform_check(&check);
            (check, result)
        })
        .collect();

    let failed = checks_with_results
        .iter()
        .any(|(_check, result)| result.is_err());
    if failed {
        println!("Outage detected - creating GitHub issue");
        // It may be worth hitting the github endpoint even if the tests pass, just
        // to check that the access is still working. Perhaps even a weekly issue
        // if the system is healthy would be useful to ensure the monitoring solution
        // doesn't break.
        make_issue(&checks_with_results).unwrap();
    } else {
        println!("All checks completed. All services OK.");
    }
}

fn get_name_servers() -> Vec<NameServer> {
    // Ideally we'd parse the ansible config for this information.
    let ns1 = NameServer {
        address: "173.255.245.83".parse().unwrap(),
        name: Name::from_str("ns1.rhiyo.com.").unwrap(),
    };
    let ns2 = NameServer {
        address: "212.71.246.209".parse().unwrap(),
        name: Name::from_str("ns2.rhiyo.com.").unwrap(),
    };

    vec![ns1, ns2]
}

fn get_checks(name_servers: &Vec<NameServer>) -> Vec<Check> {
    let mut checks = vec![];

    for name_server in name_servers {
        // Right now the DNS servers are only configured with records for themselves. Again
        // this information would ideally be parsed from the zonefile / ansible config
        // so when additional zones or hosts are added new checks would automatically start.
        for record_to_request in name_servers {
            let check = Check {
                name_server,
                record_to_request: &record_to_request.name,
                expected_ip: &record_to_request.address,
            };

            checks.push(check);
        }
    }

    checks
}

fn make_issue(checks: &Vec<(Check, Result<(), ()>)>) -> hubcaps::Result<()> {
    use futures::stream::Stream;
    use tokio::runtime::Runtime;

    use hubcaps::comments::CommentOptions;
    use hubcaps::issues::{Issue, IssueListOptions, IssueOptions, State};
    use hubcaps::{Credentials, Github};
    let github_api_key = dotenv::var("GITHUB_API_KEY").unwrap();

    let mut rt = Runtime::new()?;
    let github = Github::new(
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
        Credentials::Token(github_api_key),
    );
    let repo = github.repo("joshmcguigan", "infra");
    let existing_outage_issues: Vec<Issue> = rt.block_on(
        repo.issues()
            .iter(
                &IssueListOptions::builder()
                    .per_page(100)
                    .state(State::Open)
                    .build(),
            )
            .filter(|issue| issue.title.contains(ISSUE_TITLE))
            .collect(),
    )?;

    // If there is more than one currently open outage issue, this takes the first. Perhaps
    // it would be better to take the newest.
    //
    // For now, there should only ever be at most one open outage issue unless one is
    // manually closed, then an issue happens triggering automatic issue creation, then
    // the older issue is manually re-opened.
    //
    // It might be nice to have some "timeout" for open outage issues, so that if some time
    // has past since the last comment in an outage issue a new issue is created rather than
    // bumping the existing issue.
    match existing_outage_issues.first() {
        Some(existing_issue) => {
            // Unfortunately the API does not seem to have a nice way to get issue number, so
            // it must be parsed from the issue URL. Note issue number is not the same as
            // issue ID.
            let issue_number: u64 = existing_issue
                .url
                .split("/")
                .last()
                .unwrap()
                .parse()
                .unwrap();
            rt.block_on(repo.issue(issue_number).comments().create(&CommentOptions {
                body: format_check_results(&checks),
            }))?;
        }
        None => {
            // Create new outage issue
            rt.block_on(repo.issues().create(&IssueOptions::new(
                ISSUE_TITLE,
                Some(format_check_results(&checks)),
                Option::<String>::None,
                None,
                Vec::<String>::new(),
            )))?;
        }
    }

    Ok(())
}

fn perform_check(check: &Check) -> Result<(), ()> {
    let socket_addr = SocketAddr::new(IpAddr::V4(check.name_server.address), 53);
    let conn = UdpClientConnection::new(socket_addr).unwrap();
    let client = SyncClient::new(conn);

    let retries = 2;
    let response = perform_query_with_retries(client, check, retries)?;
    let answers: &[Record] = response.answers();

    if let RData::A(ref ip) = answers[0].rdata() {
        if ip == check.expected_ip {
            Ok(())
        } else {
            Err(())
        }
    } else {
        Err(())
    }
}

fn perform_query_with_retries(
    client: SyncClient<UdpClientConnection>,
    check: &Check,
    retries: usize,
) -> Result<DnsResponse, ()> {
    let res = client.query(&check.record_to_request, DNSClass::IN, RecordType::A);

    match (res, retries) {
        (Ok(res), _) => Ok(res),
        (Err(_), 0) => Err(()),
        (Err(_), retries) => perform_query_with_retries(client, check, retries - 1),
    }
}

fn format_check_results(checks: &Vec<(Check, Result<(), ()>)>) -> String {
    let mut s = String::from("Automated outage report\n\n");

    for (check, result) in checks {
        s += &format!(
            "Server {} resolving {} {}\n",
            check.name_server.name,
            check.record_to_request,
            if result.is_ok() { "PASS" } else { "FAIL" },
        );
    }

    s
}

#[cfg(test)]
mod tests {
    use super::{format_check_results, get_checks, get_name_servers, Check, Name};
    use std::str::FromStr;

    #[test]
    fn format() {
        let name_servers = get_name_servers();
        let checks = get_checks(&name_servers);
        let checks_with_results: Vec<(Check, Result<(), ()>)> = checks
            .into_iter()
            .map(|check| {
                // simulate failure of NS2
                let ns2 = Name::from_str("ns2.rhiyo.com.").unwrap();
                let result = if check.name_server.name == ns2 {
                    Err(())
                } else {
                    Ok(())
                };
                (check, result)
            })
            .collect();

        let output_string = format_check_results(&checks_with_results);

        assert_eq!("Automated outage report\n\nServer ns1.rhiyo.com. resolving ns1.rhiyo.com. PASS\nServer ns1.rhiyo.com. resolving ns2.rhiyo.com. PASS\nServer ns2.rhiyo.com. resolving ns1.rhiyo.com. FAIL\nServer ns2.rhiyo.com. resolving ns2.rhiyo.com. FAIL\n", output_string);
    }
}
