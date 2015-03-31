#Send SMS in Ruby

Why sign your requests instead of using basic authentication? It's much more secure, and Sinch doesn't support basic authentication for production applications.

**Note:** This has the same functionality as our Ruby gem for sending SMS [www.sinch.com/tutorials/send-sms-ruby](https://www.sinch.com/tutorials/send-sms-ruby/)

To get started, I'll show you how to sign a request to send an SMS. Create an empty ruby file - I'll call mine **sms.rb** - and add the following:

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

Then, fill in the first four variables with a phone number that can receive sms (with country code!), the text of the message you want to send, and your app key and secret from the Sinch dashboard.

If you don't yet have a Sinch account, head over to [www.sinch.com/signup](https://www.sinch.com/signup) to create an account. Then click 'create new app' to make your first app. This will generate a key and secret for you to use.

To run sms.rb, type the following onto your command line:

	ruby sms.rb

If successful, you will see the message id printed, and you will receive the text in a few seconds.

##Debugging Tips

- Use the example at [https://www.sinch.com/docs/rest-apis/api-documentation/#applicationsignedrequest](https://www.sinch.com/docs/rest-apis/api-documentation/#applicationsignedrequest) with the sample app key and secret to make sure that your signature matches the example at different points along the way
- Capitalization matters! The headers that you send with the request need to be **exactly** the same as the ones in your canonicalized_headers. Same goes for content-type.

