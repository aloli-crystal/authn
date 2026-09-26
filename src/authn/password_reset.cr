require "email"
require "./smtp_config"
require "./token"

module Authn
  # Module de réinitialisation de mot de passe par courriel.
  # Génère un token JWT signé à durée limitée et envoie un courriel
  # avec un lien de réinitialisation.
  module PasswordReset
    DEFAULT_EXPIRY = 1.hour

    record SendResult, success : Bool, error : String?

    # Génère un token de réinitialisation JWT.
    def self.generate_token(email : String, secret : String, expiry : Time::Span = DEFAULT_EXPIRY) : String
      raise ArgumentError.new("L'adresse courriel ne peut pas être vide") if email.empty?
      raise ArgumentError.new("La clé secrète ne peut pas être vide") if secret.empty?
      expiry_hours = [1, (expiry.total_hours).ceil.to_i].max
      Token.generate(
        secret: secret,
        sub: email,
        email: email,
        role: "password_reset",
        expiry_hours: expiry_hours
      )
    end

    # Envoie un courriel de réinitialisation de mot de passe.
    def self.send_reset_email(
      email : String,
      reset_url : String,
      secret : String,
      smtp : SmtpConfig,
      app_name : String = "La Table de Gaya",
      expiry : Time::Span = DEFAULT_EXPIRY,
    ) : SendResult
      return SendResult.new(success: false, error: "Configuration SMTP manquante.") if smtp.host.empty?

      token = generate_token(email, secret, expiry)
      link = "#{reset_url}?token=#{token}"
      expiry_minutes = (expiry.total_minutes).to_i

      body_text = <<-TEXT
      Réinitialisation de votre mot de passe — #{app_name}

      Vous avez demandé la réinitialisation de votre mot de passe.
      Cliquez sur le lien suivant pour définir un nouveau mot de passe :

      #{link}

      Ce lien est valide pendant #{expiry_minutes} minutes.

      Si vous n'avez pas fait cette demande, ignorez ce message.

      — #{app_name}
      TEXT

      body_html = <<-HTML
      <!DOCTYPE html>
      <html lang="fr">
      <head><meta charset="UTF-8"></head>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
        <h2 style="color: #363636;">#{app_name}</h2>
        <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="#{link}" style="background-color: #363636; color: #fff; padding: 14px 28px; text-decoration: none; border-radius: 4px; font-size: 16px;">
            Réinitialiser mon mot de passe
          </a>
        </p>
        <p style="color: #888; font-size: 13px;">Ce lien est valide pendant <strong>#{expiry_minutes} minutes</strong>.</p>
        <p style="color: #888; font-size: 13px;">Si vous n'avez pas fait cette demande, ignorez ce message.</p>
        <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 20px 0;">
        <p style="color: #bdc3c7; font-size: 12px;">L'équipe #{app_name}</p>
      </body>
      </html>
      HTML

      begin
        helo = smtp.from_address.split("@").last? || "localhost"
        config = EMail::Client::Config.new(smtp.host, smtp.port, helo_domain: helo)
        config.use_tls(EMail::Client::TLSMode::STARTTLS) if smtp.use_starttls
        config.use_tls(EMail::Client::TLSMode::SMTPS) if smtp.use_tls
        config.use_auth(smtp.username, smtp.password) unless smtp.username.empty?

        EMail::Client.new(config).start do
          message = EMail::Message.new
          # from(adresse, nom?) : deux arguments séparés — la librairie EMail refuse "Nom <addr>"
          from_display = if smtp.from_name.strip.empty? || smtp.from_name.includes?("@")
                           nil
                         else
                           smtp.from_name.strip
                         end
          message.from(smtp.from_address.strip, from_display)
          message.message(body_text)
          message.message_html(body_html)
          message.subject("Réinitialisation de votre mot de passe - #{app_name}")
          message.to(email)
          send(message)
        end

        SendResult.new(success: true, error: nil)
      rescue ex : Exception
        SendResult.new(success: false, error: ex.message)
      end
    end

    # Vérifie un token de réinitialisation et retourne l'email associé.
    # Lève Token::InvalidTokenError si le token est invalide ou expiré.
    def self.verify_token(token : String, secret : String) : String
      payload = Token.decode(token, secret)
      unless payload.role == "password_reset"
        raise Token::InvalidTokenError.new("Type de token invalide.")
      end
      payload.email
    end
  end
end
