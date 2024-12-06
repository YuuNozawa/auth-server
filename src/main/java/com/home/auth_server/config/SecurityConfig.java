package com.home.auth_server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final DataSource dataSource;

    @Value("${spring.security.oauth2.authorizationserver.issuer-uri}")
    private String issuerUri;

    // クライアント情報の読み込み
    @Value("${client.ococa.client-id}")
    private String clientId;

    @Value("${client.ococa.redirect-uri}")
    private String redirectUri;

    @Value("${client.post-logout-redirect-uri}")
    private String postLogoutRedirectUri;

    @Value("${client.ococa.cors.allowed-origin}")
    private String allowedOrigin;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }
    
    @Bean 
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // OAuth2AuthorizationServerConfigurerのインスタンスを作成
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        // エンドポイントマッチャー（RequestMatcher）とは、Spring Securityにおいて、
        // 特定のHTTPリクエストに対してどのセキュリティフィルターチェーン（SecurityFilterChain）
        // を適用するかを決定するために使用される仕組み.
        // authorizationServerConfigurer.getEndpointsMatcher()がOAuth2認可サーバーが提供する標準的なエンドポイント
        // (例：/oauth2/authorize、/oauth2/tokenなど)にマッチするRequestMatcherを返す
        // /userinfoエンドポイントがこのendpointsMatcherに含まれないので追加する.
        // これにより/userinfoエンドポイントへのOPTIONSリクエスト(CORSプリフライトリクエスト)が正しく処理される.
        RequestMatcher endpointsMatcher = new OrRequestMatcher(
            authorizationServerConfigurer.getEndpointsMatcher(),
            new AntPathRequestMatcher("/userinfo"),
            new AntPathRequestMatcher("/.well-known/**")
        );

        http
            .securityMatcher(endpointsMatcher)
            .authorizeHttpRequests(authorize -> authorize
                // OPTIONSメソッドを許可(CORSプリフライトリクエストを認証なしで許可)
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // OpenID Provider Configuration Information Endpointへの匿名アクセスを許可
                .requestMatchers("/.well-known/openid-configuration", "/.well-known/jwks.json").permitAll()
                // その他のエンドポイントは認証を要求
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(endpointsMatcher)
            )
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            // JWTによるリソースサーバーの設定
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            )
            .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
            )
            .apply(authorizationServerConfigurer)
            .oidc(Customizer.withDefaults()); // OpenID Connect 1.0を有効化;

        return http.build();
    }

    @Bean 
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            // フォームログインで認証サーバーフィルターチェーンからのリダイレクトを処理
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Bean
    public UserDetailsService userDetailsService() {

        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        // ユーザー情報の取得クエリをカスタマイズ
        userDetailsManager.setUsersByUsernameQuery(
            "SELECT user_id as username, password, true as enabled FROM users WHERE user_id = ?"
        );
    
        // ユーザーの権限情報の取得クエリをカスタマイズ
        userDetailsManager.setAuthoritiesByUsernameQuery(
            "SELECT user_id as username, authority FROM user_authorities WHERE user_id = ?"
        );
        return userDetailsManager;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean 
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient reactClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(redirectUri)
            .postLogoutRedirectUri(postLogoutRedirectUri)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .clientSettings( ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(true)
                .build() 
            )
            .build();

        return new InMemoryRegisteredClientRepository(reactClient);
    }

    @Bean 
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() { 
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean 
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean 
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuerUri).build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(allowedOrigin));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        config.setExposedHeaders(Arrays.asList("Authorization"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

