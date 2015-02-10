require "base64"
require "openssl"
require "time"
require "net/http"
require "uri"
require "json"

to = "phone_number_with_country_code"
message = "your_message"
key = "your_app_key"
secret = "you_app_secret"

body = "{\"message\":\"" + message + "\"}"
timestamp = Time.now.iso8601
http_verb = "POST"
path = "/v1/sms/" + to
scheme = "Application"
content_type = "application/json"
digest = OpenSSL::Digest.new('sha256')
canonicalized_headers = "x-timestamp:" + timestamp
content_md5 = Base64.encode64(Digest::MD5.digest(body.encode("UTF-8"))).strip
string_to_sign = http_verb + "\n" + content_md5 + "\n" + content_type + "\n" + canonicalized_headers + "\n" + path        
signature = Base64.encode64(OpenSSL::HMAC.digest(digest, Base64.decode64(secret), string_to_sign.encode("UTF-8"))).strip
authorization = "Application " + key + ":" + signature

uri = URI.parse("https://messagingApi.sinch.com" + path)
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
headers = {"content-type" => "application/json", "x-timestamp" => timestamp, "authorization" => authorization}
request = Net::HTTP::Post.new(uri.request_uri)
request.initialize_http_header(headers)
request.body = body
puts JSON.parse(http.request(request).body)