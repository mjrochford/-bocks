use clap::Command;
use gpgme::{Context, Protocol};
use std::io::prelude::*;
use std::{
    env, fs,
    path::{Component::RootDir, Path, PathBuf},
    process,
};

fn load_password_store() -> anyhow::Result<PasswordStore> {
    let home_dir_env = env::var("HOME")
        .map_err(|e| {
            panic!("Error reading home dir: {}", e);
        })
        .ok()
        .or_else(|| {
            panic!("Home Environment varible not set"); // TODO handle windows
        })
        .unwrap();

    let password_dir = PathBuf::from(home_dir_env).join(".password-store");

    let password_store = PasswordStore::from_directory(&password_dir)?;

    Ok(password_store)
}

fn dmenu(pass_store: &PasswordStore) -> anyhow::Result<()> {
    let proc = process::Command::new("dmenu")
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .spawn()?;

    pass_store.write_list(&mut proc.stdin.unwrap())?;
    let mut s = String::new();
    proc.stdout.unwrap().read_to_string(&mut s)?;

    print!("{}", pass_store.get_password(s.trim())?);
    Ok(())
}

fn main() {
    let matches = Command::new("bocks")
        .version("0.1.0")
        .about("unix password helper")
        .arg(clap::arg!(-f --find [SEARCH] "String to search password store for"))
        .arg(clap::arg!(-l --list ... "List all passwords in password store"))
        .arg(clap::arg!(-s --show [LOC] "Print the password at the location to stdout"))
        .arg(clap::arg!(-d --dmenu ... "Dmenu integration"))
        .get_matches();
    let pass_store = load_password_store().expect("Load password failed");

    if matches.is_present("list") {
        pass_store
            .write_list(&mut std::io::stdout())
            .map_err(|e| panic!("{}", e))
            .ok();
    } else if let Some(search) = matches.value_of("find") {
        let matches = pass_store
            .search(search)
            .map_err(|e| {
                panic!("{}", e);
            })
            .expect("no err");

        if matches.len() == 1 {
            let pass = pass_store
                .get_password(&matches[0])
                .map_err(|e| {
                    panic!("{}", e);
                })
                .expect("no err");
            println!("{}", pass);
        } else {
            matches.iter().for_each(|m| println!("{}", m));
        }
    } else if let Some(location) = matches.value_of("show") {
        let pass = pass_store
            .get_password(location)
            .map_err(|e| {
                panic!("{}", e);
            })
            .expect("no err");
        println!("{}", pass);
    } else if matches.is_present("dmenu") {
        dmenu(&pass_store)
            .map_err(|e| {
                panic!("{}", e);
            })
            .unwrap();
    }
}

struct PasswordStore {
    root: PathBuf,
    files: Vec<fs::DirEntry>,
}

struct Password {
    val: String,
}

impl PasswordStore {
    fn decrypt_file(file_path: &Path) -> Result<Password, anyhow::Error> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
        let mut input = fs::File::open(file_path)?;
        let mut output = Vec::new();
        let _result = ctx.decrypt(&mut input, &mut output)?;
        let pass = String::from_utf8(output)?;
        Ok(Password { val: pass })
    }

    fn get_relative_path(self: &Self, path2: &Path) -> PathBuf {
        let mut path = PathBuf::new();
        path2
            .components()
            .zip(self.root.components().chain(std::iter::repeat(RootDir)))
            .skip_while(|(a, b)| a == b)
            .for_each(|(a, _)| path.push(a));
        path
    }

    fn search(self: &Self, s: &str) -> anyhow::Result<Vec<String>> {
        let re = regex::Regex::new(s)?;
        Ok(self
            .files
            .iter()
            .map(|file| String::from(self.get_relative_path(&file.path()).to_str().unwrap()))
            .filter(|s| re.is_match(s))
            .collect())
    }

    fn write_list(self: &Self, w: &mut dyn std::io::Write) -> anyhow::Result<()> {
        for pass_file in &self.files {
            write!(
                w,
                "{}\n",
                self.get_relative_path(&pass_file.path())
                    .to_str()
                    .unwrap_or("error")
            )?;
        }
        Ok(())
    }

    fn get_password(self: &Self, name: &str) -> Result<String, anyhow::Error> {
        let pass_path = Path::new(name);
        let mut root_path = self.root.clone();
        for c in pass_path.components() {
            root_path.push(c);
        }

        let password = Self::decrypt_file(&root_path)?;
        Ok(password.val)
    }

    fn from_directory(path: &Path) -> anyhow::Result<Self> {
        let mut self_vec = Vec::new();
        let password_store = std::fs::read_dir(path)?;
        for entry in password_store {
            let node = entry?;
            if let Some(file_name_str) = node.file_name().to_str() {
                if file_name_str.chars().next().unwrap() != '.' {
                    if node.file_type()?.is_dir() {
                        let mut sub_paths = Self::from_directory(&node.path())?;
                        self_vec.append(&mut sub_paths.files);
                    } else {
                        self_vec.push(node);
                    }
                }
            }
        }

        let path = PathBuf::from(path);
        Ok(Self {
            root: path,
            files: self_vec,
        })
    }
}
