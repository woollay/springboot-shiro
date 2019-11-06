package com.justinsoft.configure;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.context.annotation.Configuration;

/**
 * Spring启动配置类，此处主要是屏蔽Springboot默认会带的dao层加载
 *
 * @since: JDK 1.8
 */
@Configuration
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class,
    DataSourceTransactionManagerAutoConfiguration.class})
public class SpringConfigure
{
}