use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::str::FromStr;

use hyper::Uri;
use lazy_static::lazy_static;
use serde::Deserialize;

lazy_static! {
    static ref RE_COUNTRIES: regex::Regex =
        regex::Regex::new(r"(?P<country>香港|美国|新加坡|台湾|日本)").unwrap();
}

#[tokio::main]
async fn main() {
    let env = include_str!("../.env");
    for line in env.lines() {
        let (k, v) = line.split_once('=').unwrap();
        env::set_var(k, v)
    }
    let mut config_file = File::create(env::var("PROFILE_PATH").unwrap()).unwrap();
    write_static_configs(&mut config_file);
    let groups = write_proxies(&mut config_file).await;
    write_rules(&mut config_file, groups);
    config_file.flush().unwrap();
}

fn write_static_configs(config_file: &mut File) {
    let static_config = include_bytes!("../clash_static_config.yaml");
    config_file.write_all(static_config).unwrap();
}

async fn write_proxies(config_file: &mut File) -> Groups {
    let mut buffer = vec![];
    let servers = get_servers().await;
    buffer.write_all(b"\nproxies:\n").unwrap();
    let mut groups = HashMap::new();
    for s in servers.into_iter().skip(2) {
        let name = s.name();
        let country = RE_COUNTRIES
            .captures(&name)
            .map_or("others", |s| s.name("country").unwrap().as_str());
        groups
            .entry(String::from(country))
            .or_insert(vec![])
            .push(name);
        let line = format!("    - {}\n", s.to_string());
        buffer.write_all(line.as_bytes()).unwrap();
    }
    config_file.write_all(&buffer).unwrap();
    groups
}

type Country = String;
type ServerName = String;

type Groups = HashMap<Country, Vec<ServerName>>;

fn write_rules(config_file: &mut File, groups: Groups) {
    config_file.write_all(b"\nproxy-groups:\n").unwrap();
    config_file
        .write_all(b"    - { name: 'Direct', type: select, proxies: [DIRECT] }\n")
        .unwrap();
    config_file
        .write_all(b"    - { name: 'Reject', type: select, proxies: [REJECT,DIRECT] }\n")
        .unwrap();
    let groups: HashMap<String, String> = groups
        .into_iter()
        .map(|(k, v)| {
            let country_en = match k.as_str() {
                "香港" => "HongKong",
                "美国" => "US",
                "新加坡" => "Singapore",
                "台湾" => "Taiwan",
                "日本" => "Japan",
                "others" => "others",
                _ => unimplemented!("countries unknown"),
            }
            .to_string();
            let proxies = v
                .into_iter()
                .map(|n| format!("'{}'", n))
                .collect::<Vec<String>>()
                .join(", ");
            (country_en, proxies)
        })
        .collect();
    config_file
        .write_all(b"    - { name: 'Unmatched', type: select, proxies: ['HongKong'] }\n")
        .unwrap();
    for (country, proxies) in &groups {
        config_file
            .write_all(
                format!(
                    "    - {{ name: '{}', type: select, proxies: [{}] }}\n",
                    country, proxies
                )
                .as_bytes(),
            )
            .unwrap();
    }
    config_file
        .write_all(b"    - { name: 'Choice', type: select, proxies: ['HongKong'] }\n")
        .unwrap();
    config_file
        .write_all(b"    - { name: 'telegram', type: select, proxies: ['US'] }\n")
        .unwrap();
    config_file.write_all(b"\nrules:\n").unwrap();
    let rules = include_bytes!("../rules");
    config_file.write_all(rules).unwrap();
}

async fn get_servers() -> Vec<Server> {
    let uri = env::var("PROFILE_URI").unwrap();
    let uri: Uri = uri.parse().unwrap();
    let https = hyper_tls::HttpsConnector::new();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    let resp = client.get(uri).await.unwrap();
    // for (k, v) in resp.headers() {
    //     println!("{}: {}", &k.to_string(), &v.to_str().unwrap());
    // }
    let body = hyper::Body::from(resp.into_body());
    let body = hyper::body::to_bytes(body).await.unwrap();
    let s = String::from_utf8(body.to_vec()).unwrap();
    let s: String = base64::decode(s)
        .unwrap()
        .into_iter()
        .map(|u| u as char)
        .collect();
    let mut servers = vec![];
    for line in s.lines() {
        let server = line.parse().unwrap();
        servers.push(server);
    }
    servers
}

#[derive(Debug)]
enum Server {
    Vmess(Vmess),
    SS(ShadowSocks),
}

impl Server {
    pub fn name(&self) -> String {
        String::from(match self {
            Server::Vmess(v) => &v.name,
            Server::SS(s) => &s.name,
        })
    }
}

#[derive(Debug, Deserialize)]
struct Vmess {
    #[serde(rename(deserialize = "v"))]
    version: String,
    #[serde(rename(deserialize = "ps"))]
    name: String,
    #[serde(rename(deserialize = "add"))]
    host: String,
    port: String,
    #[serde(rename(deserialize = "id"))]
    uuid: String,
    #[serde(rename(deserialize = "aid"))]
    alter_id: String,
}
#[derive(Debug)]
struct ShadowSocks {
    name: String,
    host: String,
    port: i32,
    cipher: String,
    password: String,
    udp: bool,
}

lazy_static! {
    static ref RE_PROTO: regex::Regex =
        regex::Regex::new(r"^(?P<p>ss|vmess)://(?P<body>.*)").unwrap();
    static ref RE_SS: regex::Regex =
        regex::Regex::new(r"(?P<cipher>.*)@(?P<server>.*)#(?P<name>.*)").unwrap();
    static ref RE_VMESS: regex::Regex = regex::Regex::new(r"").unwrap();
}

impl FromStr for Server {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cap = RE_PROTO.captures(s).unwrap();
        let proto = cap.name("p").unwrap().as_str();
        let body = cap.name("body").unwrap().as_str();
        match proto {
            "ss" => {
                let caps = RE_SS.captures(body).unwrap();
                let cipher = caps.name("cipher").unwrap().as_str();
                let cipher = String::from_utf8(base64::decode(cipher).unwrap()).unwrap();
                let (cipher, password) = cipher.split_once(':').unwrap();
                let server = caps.name("server").unwrap().as_str();
                let (host, port) = server.split_once(':').unwrap();
                let name = caps.name("name").unwrap().as_str();
                Ok(Server::SS(ShadowSocks {
                    name: urlencoding::decode(name).unwrap().to_string(),
                    host: String::from(host),
                    port: port.parse().unwrap(),
                    cipher: String::from(cipher),
                    password: String::from(password),
                    udp: true,
                }))
            }
            "vmess" => {
                let body = String::from_utf8(base64::decode(body).unwrap()).unwrap();
                Ok(Server::Vmess(serde_json::from_str(&body).unwrap()))
            }
            _ => Err("unexpected proto".into()),
        }
    }
}

impl ToString for Server {
    fn to_string(&self) -> String {
        match self {
            Server::Vmess(v) => v.to_string(),
            Server::SS(ss) => ss.to_string(),
        }
    }
}

impl ToString for ShadowSocks {
    fn to_string(&self) -> String {
        format!(
            "{{ name: '{}', type: ss, server: {}, port: {}, cipher: {}, password: {}, udp: {} }}",
            self.name, self.host, self.port, self.cipher, self.password, self.udp
        )
    }
}
impl ToString for Vmess {
    fn to_string(&self) -> String {
        format!("{{ name: '{}', type: vmess, server: {}, port: {}, uuid: {}, alterId: {}, cipher: auto, udp: true }}",
        self.name, self.host, self.port, self.uuid, self.alter_id
    )
    }
}
