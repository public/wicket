//! `wicket-policy-diff OLD.cedar NEW.cedar`: exit 0 if NEW narrows (or keeps) what OLD allows,
//! 1 if it widens (each counterexample printed), 2 on an error, a timeout or an `unknown`.

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [old, new] = args.as_slice() else {
        eprintln!("usage: wicket-policy-diff OLD.cedar NEW.cedar");
        std::process::exit(2);
    };
    let read = |p: &str| {
        std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("{p}: {e}");
            std::process::exit(2)
        })
    };
    match wicket_policy_diff::diff(&read(old), &read(new)).await {
        Ok(d) => {
            let widened: Vec<_> = d.iter().filter(|a| a.widens.is_some()).collect();
            for a in &widened {
                println!("widens {}: {}", a.action, a.widens.as_deref().unwrap_or(""));
            }
            if widened.is_empty() {
                println!("narrows (or keeps) what {old} allows, for all {} actions", d.len());
            } else {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}
