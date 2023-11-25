# Spring Security using JWT 🔐

* This project is using `Spring Boot 3.0.1` & `Spring Security 6`
* If you are using later version to `3.0.1` and respective version of spring security then you might face some deprecated code in SecurityFilterChain class.

<details>
<summary>UserDetails</summary>

* Implement the UserDetails Class to the `User` domain.
* Mark `User` domain as entity to be saved in the database, since `user` is reserved name, use `_user` or any other name instead.
* A `Subject` is the username or password, anything which will help you authenticate. Subject should be unique, so make sure to add unique constraint to subject.
* Implement all the methods required by UserDetails class.
* Make sure to turn all the booleans in those methods as `true`.


    @Entity(name = "_user")
    public class User implements UserDetails {
    
        @Id
        @GeneratedValue
        private int id;
    
        @Column(unique = true)
        private String email;
        private String name;
        private String password;
    
        @Enumerated(value = EnumType.STRING)
        private Role role;
    
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority(role.name()));
        }
    
        @Override
        public String getPassword() {
            return password;
        }
    
        @Override
        public String getUsername() {
            return email;
        }
    
        @Override
        public boolean isAccountNonExpired() {
            return true;
        }
    
        @Override
        public boolean isAccountNonLocked() {
            return true;
        }
    
        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }
    
        @Override
        public boolean isEnabled() {
            return true;
        }
    
        public String getName() {
            return name;
        }
    
        public void setName(String name) {
            this.name = name;
        }
    
        public void setEmail(String email) {
            this.email = email;
        }
    
        public void setPassword(String password) {
            this.password = password;
        }
    
        public void setRole(Role role) {
            this.role = role;
        }
    }

</details>

<details>
<summary>AuthFilter</summary>

* AuthFilter extends OncePerRequestFilter which makes sure the `doFilterInternal` executes once everytime a servlet request is handled


    @Component
    public class AuthFilter extends OncePerRequestFilter {
    
        @Override
        protected void doFilterInternal(@NonNull HttpServletRequest request,
                                        @NonNull HttpServletResponse response,
                                        @NonNull FilterChain filterChain)
                throws ServletException, IOException {
            final String authHeader = request.getHeader("Authorization");
            final String jwt;
            final String email;
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }
            jwt = authHeader.substring(7);
            email = jwtService.extractEmail(jwt);
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);
        }
    }

</details>

<details>
<summary>SecurityFilterChain</summary>

* Make sure to mark `@EnableWebSecurity` in the configuration class.
* This is where you can whitelist some of the endpoints.


    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

    @Autowired
    private AuthFilter authFilter;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf()
            .disable()
            .authorizeHttpRequests()
            .requestMatchers("/api/v1/auth/**")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}

</details>

<details>
<summary>AuthConfig</summary>

* Add these beans to be used by the authentication code


    @Configuration
    public class AuthConfig {

        @Autowired
        private UserRepository userRepository;
    
        @Bean
        public UserDetailsService userDetailsService() {
            return username -> userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        }
    
        @Bean
        public AuthenticationProvider authenticationProvider() {
            DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
            authProvider.setUserDetailsService(userDetailsService());
            authProvider.setPasswordEncoder(passwordEncoder());
            return authProvider;
        }
    
        @Bean
        AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
            return config.getAuthenticationManager();
        }
    
        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }

</details>
<details>
<summary></summary>

</details>
<details>
<summary></summary>

</details>
<details>
<summary></summary>

</details>
<details>
<summary></summary>

</details>


### Make sure to add unique email, so that there are no multiples