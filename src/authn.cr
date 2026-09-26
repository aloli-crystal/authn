require "./authn/password"
require "./authn/token"
require "./authn/session"
require "./authn/smtp_config"
require "./authn/password_reset"
require "./authn/user_manager"

# Authn — Bibliothèque d'authentification pour les applications Gaya
#
# Modules disponibles :
# - `Authn::Password`      — Hachage et validation BCrypt des mots de passe
# - `Authn::Token`         — Génération et vérification de tokens JWT
# - `Authn::Session`       — Sessions via cookies HTTP, sans framework
# - `Authn::SmtpConfig`    — Configuration du serveur SMTP
# - `Authn::PasswordReset` — Récupération de mot de passe par courriel
# - `Authn::UserManager`   — Gestion des utilisateurs administrateurs
#
# ## Utilisation rapide
#
# ```
# require "authn"
#
# # Configuration SMTP
# smtp = Authn::SmtpConfig.new(
#   host: "smtp.example.com",
#   port: 587,authn
#   username: "user@example.com",
#   password: "secret",
#   from_address: "noreply@gaya.fr",
#   from_name: "La Table de Gaya"
# )
#
# # Hachage d'un mot de passe
# hash = Authn::Password.hash("MonMotDePasse1")
#
# # Vérification
# Authn::Password.verify("MonMotDePasse1", hash) # => true
#
# # Génération d'un token JWT
# token = Authn::Token.generate(
#   secret: ENV["SESSION_SECRET"],
#   sub: "1",
#   email: "admin@gaya.fr"
# )
#
# # Envoi d'un courriel de réinitialisation
# Authn::PasswordReset.send_reset_email(
#   email: "admin@gaya.fr",
#   reset_url: "https://app.gaya.fr/admin/reset-password",
#   secret: ENV["SESSION_SECRET"],
#   smtp: smtp
# )
# ```
module Authn
  # Lue au compile-time depuis `shard.yml` via le macro `read_file`.
  # Cf. note mémoire `feedback_shard_version_macro.md` (mémoire ALOLI).
  VERSION = {{
              (read_file("#{__DIR__}/../shard.yml")
                .lines
                .find(&.starts_with?("version:")) || "version: 0.0.0")
                .gsub(/^version:\s*/, "")
                .chomp
            }}
end
