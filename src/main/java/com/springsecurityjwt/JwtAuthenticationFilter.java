package com.springsecurityjwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authheader= request.getHeader("Authorization");
        //condition for jwt token if not gound do nothing
        if(authheader==null || !authheader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authheader.substring(7);
        //pares the user  name from token
        String username= jwtService.extractusername(jwt);

        //checking if it is alfready authenticated if then
        // no need fto authenovate wiyth jwt token

        if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            //checking the username
           UserDetails userDetails=  myUserDetailsService.loadUserByUsername(username);

           //validatig the jwt token

            if(userDetails!=null && jwtService.isTokenValid(jwt))
            {
                //need to create aiuthentication token and then pass to the authenticator
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username,
                        userDetails.getPassword(),
                        userDetails.getAuthorities()
                );

                //to get the details of tghe client who is doing the request

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }



        }
        filterChain.doFilter(request, response);


    }


}
