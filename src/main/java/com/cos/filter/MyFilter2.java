package com.cos.filter;

import jakarta.servlet.*;

import java.io.IOException;

public class MyFilter2 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("===================필터2===================");
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
