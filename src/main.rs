use clap::{arg, Command};
use gpgme::{Context, KeyListMode, Protocol};
use std::io::prelude::*;
use std::{
    env,
    ffi::OsString,
    fs, io,
    path::{Component::RootDir, Path, PathBuf},
    process,
};

fn load_password_store() -> anyhow::Result<PasswordStore> {
    let home_dir_env = env::var("HOME")
        .map_err(|e| {
            panic!("{}:{} Error reading home dir: {}", file!(), line!(), e);
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

fn cb_set_contents(s: &str) -> anyhow::Result<()> {
    let xclip_proc = process::Command::new("xclip")
        .arg("-selection")
        .arg("clip")
        .stdin(process::Stdio::piped())
        .spawn()?;

    let mut xclip_stdin = xclip_proc.stdin.unwrap();
    write!(&mut xclip_stdin, "{}", s)?;
    Ok(())
}

fn dmenu(pass_store: &PasswordStore, clip: bool) -> anyhow::Result<()> {
    let dmenu_proc = process::Command::new("dmenu")
        .arg("-p")
        .arg("pass:")
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .spawn()?;

    pass_store.write_list(&mut dmenu_proc.stdin.unwrap())?;
    let mut selection_str = String::new();
    dmenu_proc
        .stdout
        .unwrap()
        .read_to_string(&mut selection_str)?;

    let password_str = pass_store.get_password(&selection_str.trim())?;

    if clip {
        cb_set_contents(&password_str).map_err(|e| {
            eprintln!("Cannot write to clipboard: {}", e);
            e
        })?;
    }
    Ok(())
}

fn main() {
    let cmd = Command::new("bocks")
        .version("0.1.0")
        .about("unix password helper")
        .arg(arg!(-f --find [SEARCH] "String to search password store for"))
        .arg(arg!(-a --add [LOC] "add new password to location"))
        .arg(arg!(-r --remove [SEARCH] "add new password to location"))
        .arg(arg!(-s --show [SEARCH] "Print the password at the location to stdout"))
        .arg(arg!(-l --list ... "List all passwords in password store"))
        .arg(arg!(-d --dmenu ... "Dmenu integration"))
        .arg(arg!(-c --clip ... "Use xclip to copy to system clipboard"))
        .subcommand(Command::new("git").allow_external_subcommands(true));
    let mut pass_store = load_password_store().expect("Load password failed");

    let matches = cmd.get_matches();

    if let Some(_) = matches.subcommand_matches("git") {
        let git_args = env::args_os()
            .skip_while(|s| s != "git")
            .collect::<Vec<OsString>>();

        let res = process::Command::new("git")
            .current_dir(pass_store.root)
            .args(&git_args[1..]) // ignore the git subcommand arg
            .output()
            .expect("Failed to run subprocess git");
        io::stdout().write_all(&res.stdout).unwrap();
        io::stderr().write_all(&res.stderr).unwrap();
    } else if matches.is_present("list") {
        pass_store
            .write_list(&mut std::io::stdout())
            .map_err(|e| panic!("{}", e))
            .ok();
    } else if let Some(search) = matches.value_of("find") {
        match pass_store.search(search) {
            Ok(pass) => {
                println!("{}", pass);
                cb_set_contents(&pass)
                    .map_err(|e| eprintln!("error setting clipboard {}", e))
                    .ok();
            }
            Err(_) => println!("Narrow your search"),
        }
    } else if let Some(location) = matches.value_of("show") {
        match pass_store.search(location) {
            Err(e) => e.iter().for_each(|p| println!("{}", p)),
            Ok(pass) => {
                println!("{}", pass);
                cb_set_contents(&pass)
                    .map_err(|e| eprintln!("error setting clipboard {}", e))
                    .ok();
            }
        }
    } else if let Some(location) = matches.value_of("remove") {
        pass_store
            .remove_password(location)
            .map_err(|e| {
                panic!("{}", e);
            })
            .ok();
    } else if let Some(location) = matches.value_of("add") {
        print!("pass: ");
        std::io::stdout()
            .flush()
            .expect("failed to write to stdout");
        let console = console::Term::stdout();
        let pass = console
            .read_secure_line()
            .map_err(|e| {
                eprintln!("error {}", e);
            })
            .expect("no err");
        pass_store
            .add_password(location, &pass)
            .map_err(|e| {
                panic!("{}", e);
            })
            .expect("noerr");
    } else if matches.is_present("dmenu") {
        dmenu(&pass_store, matches.is_present("clip"))
            .map_err(|e| {
                eprintln!("error {}", e);
            })
            .ok();
    }
}

struct PasswordStore {
    root: PathBuf,
    files: Vec<fs::DirEntry>,
}

impl PasswordStore {
    fn decrypt_file(file_path: &Path) -> anyhow::Result<String> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
        let mut input = fs::File::open(file_path)?;
        let mut output = Vec::new();
        let _result = ctx.decrypt(&mut input, &mut output)?;
        let pass = String::from_utf8(output)?;
        Ok(pass)
    }

    fn get_relative_path(&self, path2: &Path) -> PathBuf {
        let mut path = PathBuf::new();
        path2
            .components()
            .zip(self.root.components().chain(std::iter::repeat(RootDir)))
            .skip_while(|(a, b)| a == b)
            .for_each(|(a, _)| path.push(a));
        path
    }

    fn search(&self, s: &str) -> Result<String, Vec<String>> {
        match self.search_to_path(s) {
            Ok(p) => Self::decrypt_file(&p).map_err(|e| panic!("{}:{} {}", file!(), line!(), e)),
            Err(ps) => Err(ps
                .iter()
                .map(|p| String::from(p.to_str().unwrap()))
                .collect()),
        }
    }

    fn write_list(&self, w: &mut dyn std::io::Write) -> anyhow::Result<()> {
        let re = regex::Regex::new(".gpg$")?;
        self.files.iter().for_each(|pass_file| {
            self.get_relative_path(&pass_file.path())
                .to_str()
                .map(|s| re.replace(s, "").into_owned())
                .map(|loc| write!(w, "{}\n", loc));
        });
        Ok(())
    }

    fn ensure_gpg_filetype(name: &str) -> String {
        let re = regex::Regex::new(".gpg$").expect("static regex failed to compile");
        if !re.is_match(name) {
            // TODO map error case and try to find file as it was passed
            format!("{}.gpg", name)
        } else {
            String::from(name)
        }
    }

    fn search_to_path(&self, search: &str) -> Result<PathBuf, Vec<PathBuf>> {
        let re = regex::Regex::new(search).expect("error on search regex");
        let res: Vec<PathBuf> = self
            .files
            .iter()
            .map(|file| self.get_relative_path(&file.path()))
            .filter(|p| re.is_match(p.to_str().unwrap()))
            .collect();

        if res.len() == 1 {
            return Ok(res.into_iter().next().unwrap());
        } else {
            return Err(res);
        }
    }

    fn location_to_path(&self, location: &str) -> PathBuf {
        let pass_path = Path::new(location);
        let mut root_path = self.root.clone();
        for c in pass_path.components() {
            root_path.push(c);
        }
        root_path
    }

    fn remove_password(&mut self, name: &str) -> anyhow::Result<()> {
        let name = Self::ensure_gpg_filetype(name);
        fs::remove_file(self.location_to_path(&name))?;
        Ok(())
    }

    fn add_password(&mut self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = Self::ensure_gpg_filetype(name);

        let mut new_file = fs::File::create(self.location_to_path(&name))?;
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

        let mut mode = KeyListMode::empty();
        mode.insert(KeyListMode::LOCAL);
        ctx.set_key_list_mode(mode)?;
        let key = ctx
            .keys()?
            .filter_map(|x| x.ok())
            .filter(|x| x.can_encrypt())
            .next()
            .unwrap(); // TODO allow choosing which key gets used not just first one that can encrypt

        let (plaintext, mut ciphertext) = (value, Vec::new());
        ctx.encrypt(Some(&key), plaintext, &mut ciphertext)?;

        new_file.write_all(&ciphertext)?;
        Ok(())
    }

    fn get_password(&self, name: &str) -> Result<String, anyhow::Error> {
        let name = Self::ensure_gpg_filetype(name);

        Ok(Self::decrypt_file(&self.location_to_path(&name))?)
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
