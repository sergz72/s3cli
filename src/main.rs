use std::env::args;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, stdin, Write};
use s3cli_lib::{build_key_info, KeyInfo};
use s3cli_lib::azure::build_azure_key_info;

fn usage() {
    println!("Usage: s3cli key_file [get remote_file local_file][ls path][put local_file remote_file]")
}

fn main() -> Result<(), Error> {
    let arguments: Vec<String> = args().skip(1).collect();
    let l = arguments.len();
    if l < 3 || l > 4 {
        usage();
    } else {
        let data = load_file(&arguments[0])?;
        let key_info: Box<dyn KeyInfo> = if arguments[0].contains("azure") {
            Box::new(build_azure_key_info(data)?)
        } else{
            Box::new(build_key_info(data)?)
        };
        match arguments[1].as_str() {
            "get" => {
                if l != 4 {
                    usage()
                } else {
                    run_get_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "put" => {
                if l != 4 {
                    usage()
                } else {
                    run_put_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "ls" => {
                if l != 3 {
                    usage()
                } else {
                    run_ls_command(key_info, &arguments[2])?;
                }
            },
            _ => usage()
        }
    }
    Ok(())
}

fn load_file(file_name: &String) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    if file_name.starts_with("-") {
        stdin().read_to_end(&mut data)?;
    } else {
        let mut f = File::open(file_name)?;
        f.read_to_end(&mut data)?;
    }
    Ok(data)
}

fn run_get_command(key_info: Box<dyn KeyInfo>, remote_file: &String, local_file: &String) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(), &Vec::new(),
                                                   remote_file)?;
    let data = request_info.make_request(None)?;
    let mut f = File::create(local_file)?;
    f.write_all(&data)?;
    Ok(())
}

fn run_put_command(key_info: Box<dyn KeyInfo>, local_file: &String, remote_file: &String) -> Result<(), Error> {
    let data = load_file(local_file)?;
    let request_info = key_info.build_request_info("PUT",
                                                   chrono::Utc::now(), &data,
                                                   remote_file)?;
    let data = request_info.make_request(Some(data))?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    println!("{}", text);
    Ok(())
}

fn run_ls_command(key_info: Box<dyn KeyInfo>, path: &String) -> Result<(), Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(),
                                                   &Vec::new(), path)?;
    let data = request_info.make_request(None)?;
    let text = String::from_utf8(data)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    println!("{}", text);
    Ok(())
}