
// 所有具体解析器都需要实现这个 trait
pub trait Decoder {
        fn decode(&self, data: &[u8]) -> Result<String, String>;
    }
    
    #[derive(Debug, Clone)]
    pub struct DnsParser;
    impl Decoder for DnsParser {
        fn decode(&self, data: &[u8]) -> Result<String, String> {
            println!("dns parser");
            Ok(format!("Decoded Http data: {:?}", data))
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct RedisParser;
    impl Decoder for RedisParser {
        fn decode(&self, data: &[u8]) -> Result<String, String> {
            println!("redis parser");
            Ok(format!("Decoded Redis data: {:?}", data))
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct HttpParser;
    impl Decoder for HttpParser {
        fn decode(&self, data: &[u8]) -> Result<String, String> {
            println!("http parser");
            Ok(format!("Decoded Http data: {:?}", data))
        }
    }
    
    #[derive(Debug, Clone)]
    pub struct ProtoParser {
        http_parser: HttpParser,
        redis_parser: RedisParser,
        dns_parser: DnsParser,
    }
    
    impl ProtoParser {
        pub fn new() -> Self {
            ProtoParser {
                dns_parser: DnsParser,
                redis_parser: RedisParser,
                http_parser: HttpParser,
            }
        }
    
        pub fn parse_dns(&self, data: &[u8]) -> Result<String, String> {
            self.dns_parser.decode(data)
        }
    
        pub fn parse_redis(&self, data: &[u8]) -> Result<String, String> {
            self.redis_parser.decode(data)
        }
    
        pub fn parse_http(&self, data: &[u8]) -> Result<String, String> {
            self.http_parser.decode(data)
        }
    }