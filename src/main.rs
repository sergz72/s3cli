use std::env::args;
use std::fs;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, stdin, Write};
use s3cli_lib::{build_key_info, KeyInfo};
use s3cli_lib::azure::build_azure_key_info;
use s3cli_lib::qs3::QKeyInfo;

fn usage() {
    println!("Usage: s3cli key_file
    [get remote_file local_file]
    [ls path]
    [put local_file remote_file]
    [url_get remote_file]
    [url_put remote_file]
    [qget remote_file local_file]
    [qput local_file remote_file]")
}

fn build_key_info_from_file(file_name: &String) -> Result<Box<dyn KeyInfo>, Error> {
    let data = load_file(file_name)?;
    let key_info: Box<dyn KeyInfo> = if file_name.contains("azure") {
        Box::new(build_azure_key_info(data)?)
    } else{
        Box::new(build_key_info(data)?)
    };
    Ok(key_info)
}

fn build_qkey_info_from_file(file_name: &String) -> Result<Box<dyn KeyInfo>, Error> {
    let text = fs::read_to_string(file_name)?;
    let lines: Vec<String> = text
        .split('\n')
        .map(|v| v.to_string().trim().to_string())
        .collect();
    if lines.len() < 2 {
        return Err(Error::new(ErrorKind::InvalidData, "incorrect qkey file"));
    }
    let config = load_file(&lines[0])?;
    let rsa_key = fs::read_to_string(&lines[1])?;
    let qkey_info = QKeyInfo::new(config, rsa_key, 2, 3, 
                                  if lines.len() > 2 && !lines[2].is_empty() {Some(fs::read(&lines[2])?)} else {None})?;
    Ok(Box::new(qkey_info))
}

fn main() -> Result<(), Error> {
    let arguments: Vec<String> = args().skip(1).collect();
    let l = arguments.len();
    if l < 3 || l > 4 {
        usage();
    } else {
        match arguments[1].as_str() {
            "get" => {
                if l != 4 {
                    usage()
                } else {
                    let key_info = build_key_info_from_file(&arguments[0])?;
                    run_get_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "url_get" => {
                if l != 3 {
                    usage()
                } else {
                    let key_info = build_key_info_from_file(&arguments[0])?;
                    run_get_url_command(key_info, &arguments[2])?;
                }
            },
            "url_put" => {
                if l != 3 {
                    usage()
                } else {
                    let key_info = build_key_info_from_file(&arguments[0])?;
                    run_put_url_command(key_info, &arguments[2])?;
                }
            },
            "qget" => {
                if l != 4 {
                    usage()
                } else {
                    let key_info = build_qkey_info_from_file(&arguments[0])?;
                    run_get_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "put" => {
                if l != 4 {
                    usage()
                } else {
                    let key_info = build_key_info_from_file(&arguments[0])?;
                    run_put_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "qput" => {
                if l != 4 {
                    usage()
                } else {
                    let key_info = build_qkey_info_from_file(&arguments[0])?;
                    run_put_command(key_info, &arguments[2], &arguments[3])?;
                }
            },
            "ls" => {
                if l != 3 {
                    usage()
                } else {
                    let key_info = build_key_info_from_file(&arguments[0])?;
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

fn run_get_url_command(key_info: Box<dyn KeyInfo>, remote_file: &String) -> Result<(), Error> {
    let url = key_info.build_presigned_url("GET",
                                                   chrono::Utc::now(), remote_file,
                                                   60)?;
    println!("{}", url);
    Ok(())
}

fn run_put_url_command(key_info: Box<dyn KeyInfo>, remote_file: &String) -> Result<(), Error> {
    let url = key_info.build_presigned_url("PUT",
                                           chrono::Utc::now(), remote_file,
                                           60)?;
    println!("{}", url);
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