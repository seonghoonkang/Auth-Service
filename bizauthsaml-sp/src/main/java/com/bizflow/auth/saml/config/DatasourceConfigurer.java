package com.bizflow.auth.saml.config;

import com.bizflow.auth.saml.util.SecurityCipher;
import org.apache.ibatis.mapping.DatabaseIdProvider;
import org.apache.ibatis.mapping.VendorDatabaseIdProvider;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
@ImportResource()
@EnableTransactionManagement
@MapperScan(value="com.bizflow.auth.saml.dao")
public class DatasourceConfigurer {
    public static final String MAPPER_LOCATION = "classpath*:mybatis/*.xml";

    @Value("${spring.datasource.driver-class-name}") String DB_DRIVER_CLASS_NAME;
    @Value("${spring.datasource.url}") String DB_URL;
    @Value("${spring.datasource.username}") String DB_USER_NAME;
    @Value("${spring.datasource.password}") String DB_USER_PASSWORD;

    @Bean(name = "datasource")
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(DB_DRIVER_CLASS_NAME);
        dataSource.setUrl(DB_URL);
        dataSource.setUsername(DB_USER_NAME);
        dataSource.setPassword(decodePassword(DB_USER_PASSWORD));
        return dataSource;
    }

    private String decodePassword(String db_user_password) {
        String plainPassword = null;
        try {
            SecurityCipher security = SecurityCipher.getInstance();
            plainPassword = security.decipher128Base64(db_user_password);
        } catch (Exception e) {
            throw new IllegalArgumentException("Can not decryption DB Password :: " + db_user_password);
        }
        return plainPassword;
    }

    @Bean(name = "sqlSessionFactory")
    public SqlSessionFactory sqlSessionFactory(DataSource dataSource, ApplicationContext applicationContext) throws Exception {
        SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
        sqlSessionFactoryBean.setDataSource(dataSource);
        sqlSessionFactoryBean.setMapperLocations(applicationContext.getResources(MAPPER_LOCATION));
        sqlSessionFactoryBean.setDatabaseIdProvider(getDatabaseIdProvider());
        return sqlSessionFactoryBean.getObject();
    }

    @Bean(name = "sqlSession")
    public SqlSessionTemplate sqlSession(SqlSessionFactory sqlSessionFactory){
        return new SqlSessionTemplate(sqlSessionFactory);
    }
    @Bean
    public DatabaseIdProvider getDatabaseIdProvider() {
        DatabaseIdProvider databaseIdProvider = new VendorDatabaseIdProvider();
        Properties p = new Properties();
        p.setProperty("SQL Server", "mssql");
        p.setProperty("Oracle", "oracle");
        p.setProperty("MySQL", "mysql");
        databaseIdProvider.setProperties(p);
        return databaseIdProvider;
    }
}
