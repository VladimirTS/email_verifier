require 'net/smtp'
require 'dnsruby'

class EmailVerifier::Checker

  ##
  # Returns server object for given email address or throws exception
  # Object returned isn't yet connected. It has internally a list of 
  # real mail servers got from MX dns lookup
  def initialize(address, params = {})
    if params[:emails]
      @emails = params[:emails]
      @email   = address
      @domain = params[:domain]
      @servers = list_mxs @domain
      @smtp    = nil
      @user_email = EmailVerifier.config.verifier_email
      _, @user_domain = @user_email.split("@")
    else
      @email   = address
      _, @domain  = address.split("@")
      @servers = list_mxs @domain
      #raise EmailVerifier::NoMailServerException.new("No mail server for #{address}") if @servers.empty?
      @smtp    = nil

      # this is because some mail servers won't give any info unless
      # a real user asks for it:
      @user_email = EmailVerifier.config.verifier_email
      _, @user_domain = @user_email.split "@"
    end
  end

  def list_mxs(domain)
    return [] unless domain
    res = Dnsruby::DNS.new
    mxs = []
    res.each_resource(domain, 'MX') do |rr|
      mxs << { priority: rr.preference, address: rr.exchange.to_s }
    end
    mxs.sort_by { |mx| mx[:priority] }
  rescue Dnsruby::NXDomain
    raise EmailVerifier::NoMailServerException.new("#{domain} does not exist") 
  end

  def is_connected
    !@smtp.nil?
  end

  def connect
    begin
      server = next_server
      raise EmailVerifier::OutOfMailServersException.new("Unable to connect to any one of mail servers for #{@email}") if server.nil?
      @smtp = MySmtp.start server[:address], 25, @user_domain
      return true
    rescue EmailVerifier::OutOfMailServersException => e
      raise EmailVerifier::OutOfMailServersException, e.message
    rescue => e
      retry
    end
  end

  def next_server
    @servers.shift
  end

  def verify
    self.mailfrom @user_email
    if @emails.present?
      self.rcptto_list(@emails).tap do
        close_connection
      end
    else
      self.rcptto(@email).tap do
        close_connection
      end
    end
  end

  def close_connection
    @smtp.finish if @smtp && @smtp.started?
  end

  def mailfrom(address)
    ensure_connected

    ensure_250 @smtp.mailfrom(address)
  end

  def rcptto(address)
    ensure_connected
   
    begin
      ensure_250 @smtp.rcptto(address)
    rescue => e
      if e.message[/^550/]
        return false
      else
        raise EmailVerifier::FailureException.new(e.message)
      end
    end
  end


  def rcptto_list(addresses)
    ensure_connected

    begin
      @smtp.check_emails(addresses)
    rescue => e
      if e.message[/^550/]
        return false
      else
        raise EmailVerifier::FailureException.new(e.message)
      end
    end
  end

  def ensure_connected
    raise EmailVerifier::NotConnectedException.new("You have to connect first") if @smtp.nil?
  end

  def ensure_250(smtp_return)
    if smtp_return.status.to_i == 250
      return true
    else
      raise EmailVerifier::FailureException.new "Mail server responded with #{smtp_return.status} when we were expecting 250"
    end
  end
end

class MySmtp < Net::SMTP

  def check_emails(to_addrs)
    ok_users = []
    unknown_users = []
    to_addrs.flatten.each do |addr|
      begin
        rcptto addr
      rescue Net::SMTPFatalError => e
        unknown_users << addr.dump
      else
        ok_users << addr
      end
    end

    {ok_users: ok_users, unknown_users: unknown_users}
  end
end
