use chrono::{DateTime, Local};
use git2::{Error, Repository};
use std::time::{Duration, UNIX_EPOCH};

pub fn print_latest_n_commits(n: u32) -> Result<(), Error> {
    let repo = Repository::discover(".")?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(git2::Sort::TIME)?;

    for (count, oid_result) in revwalk.enumerate() {
        if count >= n as usize {
            break;
        }
        let oid = oid_result?;
        let commit = repo.find_commit(oid)?;

        let timestamp = commit.time().seconds();
        let datetime = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
        let datetime: DateTime<Local> = DateTime::from(datetime);

        println!(" Author: {}", commit.author());
        println!("  Hash: {}", commit.id());
        println!("  Date: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
        println!("  Message: {}", commit.message().unwrap_or("<no message>"));
        println!();
    }
    Ok(())
}
