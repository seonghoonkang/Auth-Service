package com.bizflow.auth.saml.config;

import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
@ImportResource()
@MapperScan(value="com.bizflow.auth.saml.dao")
public class DatabaseConfigurer {
    public static final String MAPPER_LOCATION = "classpath*:mappers/**/*.xml";

    @Value("${spring.datasorce.driver-class-name}") String MSSQL_DRIVER_CLASS_NAME;
    @Value("${spring.datasorce.url}") String MYSQL_URL;
    @Value("${spring.datasorce.username}") String MYSQL_USER_NAME;
    @Value("${spring.datasorce.password}") String MYSQL_USER_PASSWORD;

    @Bean
    public DataSource mssqlDataSource() {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();

        dataSource.setDriverClassName(MSSQL_DRIVER_CLASS_NAME);
        dataSource.setUrl(MYSQL_URL);
        dataSource.setUsername(MYSQL_USER_NAME);
        dataSource.setPassword(MYSQL_USER_PASSWORD);

        return dataSource;
    }

    @Bean
    public SqlSessionFactory sqlSessionFactory(DataSource dataSource, ApplicationContext applicationContext) throws Exception {
        SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
        sqlSessionFactoryBean.setDataSource(dataSource);
        sqlSessionFactoryBean.setMapperLocations(applicationContext.getResources(MAPPER_LOCATION));

        return sqlSessionFactoryBean.getObject();
    }
}
