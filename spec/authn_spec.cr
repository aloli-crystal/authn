require "./spec_helper"

# =============================================================================
# Tests Authn::Password
# =============================================================================
describe Authn::Password do
  describe ".hash" do
    it "hache un mot de passe valide" do
      hash = Authn::Password.hash(TEST_PASSWORD)
      hash.should_not be_empty
      hash.should start_with("$2")
    end

    it "produit des hashes différents pour le même mot de passe" do
      hash1 = Authn::Password.hash(TEST_PASSWORD)
      hash2 = Authn::Password.hash(TEST_PASSWORD)
      hash1.should_not eq(hash2)
    end

    it "lève une erreur si le mot de passe est vide" do
      expect_raises(ArgumentError, /must not be empty/) do
        Authn::Password.hash("")
      end
    end

    it "retourne false pour un mot de passe incorrect" do
      hash = Authn::Password.hash(TEST_PASSWORD)
      Authn::Password.verify("MauvaisMotDePasse1", hash).should be_false
    end

    it "retourne false si le mot de passe est vide" do
      hash = Authn::Password.hash(TEST_PASSWORD)
      Authn::Password.verify("", hash).should be_false
    end

    it "retourne false si le hash est vide" do
      Authn::Password.verify(TEST_PASSWORD, "").should be_false
    end

    it "retourne false pour un hash malformé" do
      Authn::Password.verify(TEST_PASSWORD, "hash_invalide").should be_false
    end
  end

  # Les règles de mot de passe ont quitté ce shard pour `password-policy`,
  # parce qu'elles sont une question de politique : elles changent avec le
  # régulateur — la CNIL a remplacé ses règles de composition de 2017 par des
  # paliers d'entropie en 2022 — et les garder ici imposait à chaque
  # consommateur une formulation française figée.
  describe "politique de mot de passe" do
    it "n'applique aucune politique par défaut" do
      # Court, sans majuscule ni chiffre : accepté, car vérifier le mot de
      # passe est l'affaire de l'appelant.
      Authn::Password.hash("court").should start_with("$2")
    end

    it "applique la politique qu'on lui passe" do
      expect_raises(Authn::Password::PolicyError, /too_short|TooShort/i) do
        Authn::Password.hash("court", policy: PasswordPolicy::Policy.long)
      end
    end

    it "expose les motifs de refus en valeurs, pas en phrases" do
      begin
        Authn::Password.hash("court", policy: PasswordPolicy::Policy.composed)
        fail "aurait dû lever"
      rescue ex : Authn::Password::PolicyError
        ex.violations.should contain(PasswordPolicy::Violation::TooShort)
        ex.violations.should contain(PasswordPolicy::Violation::MissingUppercase)
      end
    end

    it "hache ce que la politique accepte" do
      Authn::Password.hash("Comptabilite12", policy: PasswordPolicy::Policy.long)
        .should start_with("$2")
    end
  end

  # BCrypt tronque au-delà de 72 octets. Tronquer est pire qu'échouer : le mot
  # de passe a l'air de fonctionner alors qu'une partie est ignorée.
  describe "limite de BCrypt" do
    it "refuse au-delà de la limite" do
      expect_raises(ArgumentError, /BCrypt accepts at most 71/) do
        Authn::Password.hash("A1!" + "a" * 100)
      end
    end

    it "compte des octets, pas des caractères" do
      accente = "Éé" * 20 # 40 caractères, 80 octets
      accente.size.should eq(40)
      accente.bytesize.should eq(80)

      expect_raises(ArgumentError, /80 bytes/) do
        Authn::Password.hash(accente)
      end
    end

    # 71 et non 72 : Crystal ajoute un octet NUL (`password.bytesize + 1`) et
    # rejette au-delà de 72, si bien que 72 octets de mot de passe en font 73.
    it "accepte tout juste 71 octets, et refuse 72" do
      Authn::Password.hash("a" * 71).should start_with("$2")

      expect_raises(ArgumentError, /72 bytes; BCrypt accepts at most 71/) do
        Authn::Password.hash("a" * 72)
      end
    end
  end
end

# =============================================================================
# Tests Authn::Token
# =============================================================================
describe Authn::Token do
  describe ".generate" do
    it "génère un token JWT non vide" do
      token = Authn::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      token.should_not be_empty
      token.split(".").size.should eq(3)
    end

    it "lève une erreur si la clé secrète est vide" do
      expect_raises(ArgumentError, "secrète") do
        Authn::Token.generate(secret: "", sub: "1", email: TEST_EMAIL)
      end
    end

    it "lève une erreur si le sujet est vide" do
      expect_raises(ArgumentError, "sub") do
        Authn::Token.generate(secret: SECRET_KEY, sub: "", email: TEST_EMAIL)
      end
    end
  end

  describe ".decode" do
    it "décode un token valide" do
      token = Authn::Token.generate(secret: SECRET_KEY, sub: "42", email: TEST_EMAIL, role: "admin")
      payload = Authn::Token.decode(token, SECRET_KEY)
      payload.sub.should eq("42")
      payload.email.should eq(TEST_EMAIL)
      payload.role.should eq("admin")
      payload.expired?.should be_false
    end

    it "lève InvalidTokenError pour un token vide" do
      expect_raises(Authn::Token::InvalidTokenError, "vide") do
        Authn::Token.decode("", SECRET_KEY)
      end
    end

    it "lève InvalidTokenError pour une mauvaise clé secrète" do
      token = Authn::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      expect_raises(Authn::Token::InvalidTokenError) do
        Authn::Token.decode(token, "mauvaise_cle_secrete_suffisamment_longue")
      end
    end

    it "lève InvalidTokenError pour un token malformé" do
      expect_raises(Authn::Token::InvalidTokenError) do
        Authn::Token.decode("token.invalide.ici", SECRET_KEY)
      end
    end
  end

  describe ".valid?" do
    it "retourne true pour un token valide" do
      token = Authn::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      Authn::Token.valid?(token, SECRET_KEY).should be_true
    end

    it "retourne false pour un token invalide" do
      Authn::Token.valid?("token_invalide", SECRET_KEY).should be_false
    end

    it "retourne false pour un token vide" do
      Authn::Token.valid?("", SECRET_KEY).should be_false
    end
  end

  describe ".generate_reservation_token" do
    it "génère un token de réservation valide" do
      token = Authn::Token.generate_reservation_token(
        secret: SECRET_KEY,
        reservation_token: "abc123def456"
      )
      token.should_not be_empty
      token.split(".").size.should eq(3)
    end

    it "lève une erreur si la clé secrète est vide" do
      expect_raises(ArgumentError) do
        Authn::Token.generate_reservation_token(secret: "", reservation_token: "abc123")
      end
    end
  end
end

# =============================================================================
# Tests Authn::SmtpConfig
# =============================================================================
describe Authn::SmtpConfig do
  describe ".new" do
    it "crée une configuration avec les valeurs fournies" do
      config = Authn::SmtpConfig.new(
        host: "smtp.example.com",
        port: 587,
        username: "user@example.com",
        password: "secret",
        from_address: "noreply@example.com",
        from_name: "Test"
      )
      config.host.should eq("smtp.example.com")
      config.port.should eq(587)
      config.from_address.should eq("noreply@example.com")
    end
  end

  describe ".from_hash" do
    it "crée une configuration depuis un Hash" do
      config = Authn::SmtpConfig.from_hash({
        "smtp_host"         => "smtp.test.com",
        "smtp_port"         => "465",
        "smtp_from_address" => "test@test.com",
        "smtp_from_name"    => "Test App",
      })
      config.host.should eq("smtp.test.com")
      config.port.should eq(465)
    end
  end

  describe ".validate" do
    it "retourne un tableau vide pour une configuration valide" do
      config = Authn::SmtpConfig.new(
        host: "smtp.example.com",
        port: 587,
        from_address: "noreply@example.com"
      )
      config.validate.should be_empty
    end

    it "signale un hôte vide" do
      config = Authn::SmtpConfig.new(host: "", port: 587, from_address: "test@test.com")
      config.validate.any? { |e| e.includes?("hôte") }.should be_true
    end

    it "signale un port invalide" do
      config = Authn::SmtpConfig.new(host: "smtp.test.com", port: 0, from_address: "test@test.com")
      config.validate.any? { |e| e.includes?("port") }.should be_true
    end

    it "signale une adresse d'expédition invalide" do
      config = Authn::SmtpConfig.new(host: "smtp.test.com", port: 587, from_address: "invalide")
      config.validate.any? { |e| e.includes?("invalide") }.should be_true
    end
  end
end

# =============================================================================
# Tests Authn::PasswordReset
# =============================================================================
describe Authn::PasswordReset do
  describe ".generate_token" do
    it "génère un token de réinitialisation valide" do
      token = Authn::PasswordReset.generate_token(TEST_EMAIL, SECRET_KEY)
      token.should_not be_empty
      token.split(".").size.should eq(3)
    end

    it "lève une erreur si l'email est vide" do
      expect_raises(ArgumentError, "courriel") do
        Authn::PasswordReset.generate_token("", SECRET_KEY)
      end
    end

    it "lève une erreur si la clé secrète est vide" do
      expect_raises(ArgumentError, "secrète") do
        Authn::PasswordReset.generate_token(TEST_EMAIL, "")
      end
    end
  end

  describe ".verify_token" do
    it "retourne l'email pour un token valide" do
      token = Authn::PasswordReset.generate_token(TEST_EMAIL, SECRET_KEY)
      email = Authn::PasswordReset.verify_token(token, SECRET_KEY)
      email.should eq(TEST_EMAIL)
    end

    it "lève InvalidTokenError pour un token vide" do
      expect_raises(Authn::Token::InvalidTokenError, "vide") do
        Authn::PasswordReset.verify_token("", SECRET_KEY)
      end
    end

    it "lève InvalidTokenError pour une mauvaise clé" do
      token = Authn::PasswordReset.generate_token(TEST_EMAIL, SECRET_KEY)
      expect_raises(Authn::Token::InvalidTokenError) do
        Authn::PasswordReset.verify_token(token, "mauvaise_cle_suffisamment_longue_ici")
      end
    end

    it "lève InvalidTokenError pour un token JWT standard (mauvais type)" do
      token = Authn::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      expect_raises(Authn::Token::InvalidTokenError, "Type de token invalide") do
        Authn::PasswordReset.verify_token(token, SECRET_KEY)
      end
    end
  end
end

# =============================================================================
# Tests Authn::UserManager
# =============================================================================
describe Authn::UserManager do
  describe ".hash_password et .verify_password" do
    it "hache et vérifie correctement un mot de passe" do
      hash = Authn::UserManager.hash_password(TEST_PASSWORD)
      Authn::UserManager.verify_password(TEST_PASSWORD, hash).should be_true
      Authn::UserManager.verify_password("MauvaisMotDePasse1", hash).should be_false
    end
  end

  describe ".generate_temp_password" do
    it "génère un mot de passe de la longueur demandée" do
      pwd = Authn::UserManager.generate_temp_password(12)
      pwd.size.should eq(12)
    end

    it "génère des mots de passe différents à chaque appel" do
      pwd1 = Authn::UserManager.generate_temp_password
      pwd2 = Authn::UserManager.generate_temp_password
      pwd1.should_not eq(pwd2)
    end
  end
end
