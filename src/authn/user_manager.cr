require "email"
require "./password"
require "./password_reset"
require "./smtp_config"

module Authn
  # Module de gestion des utilisateurs administrateurs.
  # Fournit des utilitaires pour la création, la validation et l'invitation
  # des utilisateurs via courriel.
  module UserManager
    VALID_ROLES = %w[admin gestionnaire]

    # Génère un mot de passe temporaire sécurisé.
    # La longueur correspond au nombre exact de caractères retournés.
    def self.generate_temp_password(length : Int32 = 16) : String
      chars = (('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a)
      Array.new(length) { chars.sample(Random::Secure) }.join
    end

    # Hache un mot de passe via Authn::Password.
    def self.hash_password(password : String) : String
      Password.hash(password)
    end

    # Envoie un courriel d'invitation à un nouvel utilisateur.
    def self.send_invitation_email(
      email : String,
      prenom : String,
      invitation_url : String,
      secret : String,
      smtp : SmtpConfig,
      invited_by : String = "",
      app_name : String = "La Table de Gaya",
    ) : PasswordReset::SendResult
      return PasswordReset::SendResult.new(success: false, error: "Configuration SMTP manquante.") if smtp.host.empty?

      body_text = <<-TEXT
      Invitation — #{app_name}

      Bonjour #{prenom},

      Vous avez été invité(e) à rejoindre #{app_name}.
      Cliquez sur le lien suivant pour activer votre compte et définir votre mot de passe :

      #{invitation_url}

      Ce lien est valide pendant 24 heures.

      — #{app_name}
      TEXT

      body_html = <<-HTML
      <!DOCTYPE html>
      <html lang="fr">
      <head><meta charset="UTF-8"></head>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
        <h2 style="color: #363636;">#{app_name}</h2>
        <p>Bonjour <strong>#{prenom}</strong>,</p>
        <p>Vous avez été invité(e) à rejoindre <strong>#{app_name}</strong>.</p>
        <p>Cliquez sur le bouton ci-dessous pour activer votre compte :</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="#{invitation_url}" style="background-color: #363636; color: #fff; padding: 14px 28px; text-decoration: none; border-radius: 4px; font-size: 16px;">
            Activer mon compte
          </a>
        </p>
        <p style="color: #888; font-size: 13px;">Ce lien est valide pendant <strong>24 heures</strong>.</p>
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
          message.subject("Invitation - #{app_name}")
          message.to(email)
          send(message)
        end

        PasswordReset::SendResult.new(success: true, error: nil)
      rescue ex : Exception
        PasswordReset::SendResult.new(success: false, error: ex.message)
      end
    end

    # Valide les champs d'un utilisateur. Retourne une liste d'erreurs.
    #
    # Ne valide plus le mot de passe : ces règles vivent dans
    # `password-policy`, où elles suivent la recommandation CNIL en vigueur.
    # Appeler `PasswordPolicy::Policy#validate` à côté de celle-ci.
    def self.validate_user(email : String, nom : String, prenom : String, role : String) : Array(String)
      errors = [] of String
      errors << "L'adresse courriel est invalide." unless email.includes?("@") || email.empty?
      errors << "L'adresse courriel est requise." if email.empty?
      errors << "Le nom est requis." if nom.empty?
      errors << "Le prénom est requis." if prenom.empty?
      errors << "Le rôle est invalide." unless VALID_ROLES.includes?(role)
      errors
    end

    # Vérifie un mot de passe contre son hash.
    def self.verify_password(password : String, hash : String) : Bool
      Password.verify(password, hash)
    end
  end
end
