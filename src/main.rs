use std::fs::File;
use std::path::Path;
use tar::Archive;
use zeroize::Zeroize;
mod crypto;
use anyhow::anyhow;
use clap::Parser;
use std::fs;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// 'encrypt' or 'decrypt'
    action: String,

    /// Path to the input file
    #[clap(short, long, value_parser)]
    input: String,

    /// Path to the output file
    #[clap(short, long, value_parser)]
    output: String,

    /// Delete the source file after (en)decryption
    #[clap(long, value_parser, default_value_t = false)]
    delete: bool,
}

fn pack_directory(src_path: &str) -> Result<String, anyhow::Error> {
    let src_path_tar = format!("{}.tar", src_path);

    let file = File::create(&src_path_tar)?;

    let mut tar = tar::Builder::new(file);
    tar.append_dir_all(".", src_path)?;
    tar.finish()?;

    Ok(src_path_tar)
}

fn unpack_directory(src_path: &str, dst_path: &str) -> Result<(), anyhow::Error> {
    let tar = File::open(&src_path)?;

    let mut archive = Archive::new(tar);
    archive.unpack(dst_path).unwrap();

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    // Get the file/folder name to encrypt
    let source_path = args.input;
    let dest_path = args.output;

    if !(args.action == "decrypt" || args.action == "encrypt") {
        return Err(anyhow!("Provide a valid action: 'encrypt' or 'decrypt'"));
    }

    // Prompt the user for the password
    let mut password = rpassword::prompt_password("Enter the password:").unwrap();

    // ENCRYPT the file
    if args.action == "encrypt" {
        // Ask for password confirmation
        let mut confirm_password = rpassword::prompt_password("Confirm the password:").unwrap();
        if password != confirm_password {
            return Err(anyhow!("Passwords do not match."));
        }
        confirm_password.zeroize();

        let is_dir = Path::new(&source_path).is_dir();

        if is_dir {
            let source_path_tar = pack_directory(&source_path)?;

            // Append .tar.enc if the source is a directory
            let dest_path_tar = format!("{}.tar.enc", dest_path);

            crypto::encrypt_file(&source_path_tar, &dest_path_tar, &password)?;
            fs::remove_file(source_path_tar)?;

            if args.delete {
                fs::remove_dir_all(source_path)?;
            }
        } else {
            crypto::encrypt_file(&source_path, &dest_path, &password)?;

            if args.delete {
                fs::remove_file(source_path)?;
            }
        }

    // DECRYPT the file
    } else {
        let is_dir = source_path.contains(".tar.enc");

        if is_dir {
            let tar_temp_dst = format!("{}.dec", dest_path);
            crypto::decrypt_file(&source_path, &tar_temp_dst, &password)?;
            unpack_directory(&tar_temp_dst, &dest_path)?;
            fs::remove_file(tar_temp_dst)?;
        } else {
            crypto::decrypt_file(&source_path, &dest_path, &password)?;
        }

        if args.delete {
            fs::remove_file(&source_path)?;
        }
    }

    // Clear password from memory
    password.zeroize();

    Ok(())
}
