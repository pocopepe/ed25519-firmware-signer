use git2::{Error, Repository};

pub fn _print_latest_commit_hash() -> Result<(), Error> {
    let repo = Repository::discover(".")?;
    let head = repo.head()?;
    let commit = head.peel_to_commit()?;

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;

    let count = revwalk.count();

    println!("Latest commit hash: {}", commit.id());
    println!("Commit message: {}", commit.message().unwrap_or("<no message>"));
    println!("number of commits: {}", count);

    Ok(())
}



