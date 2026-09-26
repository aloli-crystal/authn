require "./token"

module Authn
  # Gestion des sessions d'authentification via cookies HTTP.
  # Ne dépend d'aucun framework : `create_cookie` rend un `HTTP::Cookie` de la
  # bibliothèque standard, que l'appelant attache à sa réponse comme il
  # l'entend. C'est ce qui rendait l'ancien nom `kemal-auth` trompeur.
  module Session
    COOKIE_HTTPONLY = true
    COOKIE_NAME     = "aloli_auth_token"
    COOKIE_PATH     = "/"
    COOKIE_SECURE   = true

    # Résultat d'une vérification de session
    record SessionInfo,
      authenticated : Bool,
      payload : Token::Payload?,
      error : String? do
      def authenticated? : Bool
        authenticated
      end
    end

    # Vérifie si la session est authentifiée (version simplifiée).
    #
    # ```
    # Authn::Session.authenticated?(cookies, secret: "ma_cle_secrete")
    # ```
    def self.authenticated?(cookies : HTTP::Cookies, secret : String) : Bool
      verify(cookies, secret).authenticated?
    end

    # Crée un cookie de session sécurisé à partir d'un token JWT.
    # Retourne un objet HTTP::Cookie prêt à être ajouté à la réponse.
    #
    # ```
    # cookie = Authn::Session.create_cookie(token, expiry_hours: 8)
    # env.response.cookies << cookie
    # ```
    def self.create_cookie(
      token : String,
      expiry_hours : Int32 = Token::DEFAULT_EXPIRY_HOURS,
      secure : Bool = COOKIE_SECURE,
    ) : HTTP::Cookie
      HTTP::Cookie.new(
        name: COOKIE_NAME,
        value: token,
        path: COOKIE_PATH,
        expires: Time.utc + expiry_hours.hours,
        secure: secure,
        http_only: COOKIE_HTTPONLY,
        samesite: HTTP::Cookie::SameSite::Strict
      )
    end

    # Crée un cookie de déconnexion (valeur vide, expiration passée).
    #
    # ```
    # env.response.cookies << Authn::Session.logout_cookie
    # ```
    def self.logout_cookie : HTTP::Cookie
      HTTP::Cookie.new(
        name: COOKIE_NAME,
        value: "",
        path: COOKIE_PATH,
        expires: Time.utc - 1.hour,
        secure: COOKIE_SECURE,
        http_only: COOKIE_HTTPONLY
      )
    end

    # Extrait et vérifie le token de session depuis les cookies de la requête.
    # Retourne un `SessionInfo` avec le résultat de la vérification.
    #
    # ```
    # info = Authn::Session.verify(cookies, secret: "ma_cle_secrete")
    # if info.authenticated?
    #   puts info.payload.not_nil!.email
    # end
    # ```
    def self.verify(
      cookies : HTTP::Cookies,
      secret : String,
    ) : SessionInfo
      token = cookies[COOKIE_NAME]?.try(&.value)

      return SessionInfo.new(
        authenticated: false,
        payload: nil,
        error: "Aucun token de session trouvé"
      ) if token.nil? || token.empty?

      payload = Token.decode(token, secret)
      SessionInfo.new(authenticated: true, payload: payload, error: nil)
    rescue ex : Token::InvalidTokenError
      SessionInfo.new(authenticated: false, payload: nil, error: ex.message)
    end
  end
end
