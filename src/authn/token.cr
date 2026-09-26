require "jwt"
require "json"

module Authn
  # Gestion des tokens JWT pour l'authentification sans état.
  # Génère, vérifie et décode les tokens d'accès et de session.
  module Token
    # Durée de validité par défaut d'un token (8 heures)
    DEFAULT_EXPIRY_HOURS = 8

    # Erreur levée lorsqu'un token est invalide ou expiré
    class InvalidTokenError < Exception; end

    # Représente le contenu décodé d'un token valide
    record Payload,
      sub : String,
      email : String,
      role : String,
      exp : Int64,
      iat : Int64 do
      def expired? : Bool
        Time.utc.to_unix >= exp
      end

      def expires_at : Time
        Time.unix(exp)
      end
    end

    # Décode et vérifie un token JWT.
    # Lève `InvalidTokenError` si le token est invalide, expiré ou mal formé.
    #
    # ```
    # payload = Authn::Token.decode(token, secret: "ma_cle_secrete")
    # puts payload.email
    # ```
    def self.decode(token : String, secret : String) : Payload
      raise InvalidTokenError.new("Le token ne peut pas être vide") if token.empty?
      raise InvalidTokenError.new("La clé secrète ne peut pas être vide") if secret.empty?

      payload_hash, _header = JWT.decode(token, secret, JWT::Algorithm::HS256)
      hash = payload_hash.as_h

      sub = hash["sub"]?.try(&.as_s) || raise InvalidTokenError.new("Champ 'sub' manquant")
      email = hash["email"]?.try(&.as_s) || ""
      role = hash["role"]?.try(&.as_s) || "admin"
      exp = hash["exp"]?.try(&.as_i64) || raise InvalidTokenError.new("Champ 'exp' manquant")
      iat = hash["iat"]?.try(&.as_i64) || 0_i64

      p = Payload.new(sub: sub, email: email, role: role, exp: exp, iat: iat)
      raise InvalidTokenError.new("Le token a expiré") if p.expired?
      p
    rescue JWT::ExpiredSignatureError
      raise InvalidTokenError.new("Le token a expiré")
    rescue ex : JWT::DecodeError
      raise InvalidTokenError.new("Token invalide : #{ex.message}")
    end

    # Génère un token JWT signé pour un utilisateur authentifié.
    #
    # ```
    # token = Authn::Token.generate(
    #   secret: "ma_cle_secrete",
    #   sub: "42",
    #   email: "admin@gaya.fr",
    #   role: "admin"
    # )
    # ```
    def self.generate(
      secret : String,
      sub : String,
      email : String,
      role : String = "admin",
      expiry_hours : Int32 = DEFAULT_EXPIRY_HOURS,
    ) : String
      raise ArgumentError.new("La clé secrète ne peut pas être vide") if secret.empty?
      raise ArgumentError.new("Le sujet (sub) ne peut pas être vide") if sub.empty?

      now = Time.utc.to_unix
      payload = {
        "sub"   => sub,
        "email" => email,
        "role"  => role,
        "exp"   => (Time.utc + expiry_hours.hours).to_unix,
        "iat"   => now,
      }
      JWT.encode(payload, secret, JWT::Algorithm::HS256)
    end

    # Génère un token à usage unique pour un lien de réservation client.
    # Ce token a une durée de vie plus longue (72h par défaut).
    #
    # ```
    # token = Authn::Token.generate_reservation_token(
    #   secret: "ma_cle_secrete",
    #   reservation_token: "abc123",
    #   expiry_hours: 72
    # )
    # ```
    def self.generate_reservation_token(
      secret : String,
      reservation_token : String,
      expiry_hours : Int32 = 72,
    ) : String
      raise ArgumentError.new("La clé secrète ne peut pas être vide") if secret.empty?

      payload = {
        "sub"  => reservation_token,
        "type" => "reservation",
        "exp"  => (Time.utc + expiry_hours.hours).to_unix,
        "iat"  => Time.utc.to_unix,
      }
      JWT.encode(payload, secret, JWT::Algorithm::HS256)
    end

    # Vérifie si un token est valide sans lever d'exception.
    # Retourne true si le token est valide et non expiré.
    #
    # ```
    # Authn::Token.valid?(token, secret: "ma_cle_secrete") # => true ou false
    # ```
    def self.valid?(token : String, secret : String) : Bool
      decode(token, secret)
      true
    rescue InvalidTokenError
      false
    end
  end
end
