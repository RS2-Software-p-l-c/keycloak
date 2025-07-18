/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.quarkus.runtime.configuration.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.quarkus.runtime.Environment.isWindows;

import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import io.smallrye.config.SmallRyeConfig;
import org.hibernate.dialect.H2Dialect;
import org.hibernate.dialect.PostgreSQLDialect;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.Expressions;
import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.h2.Driver;
import org.hibernate.dialect.MariaDBDialect;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.Config;
import org.keycloak.config.CachingOptions;
import org.keycloak.quarkus.runtime.configuration.ConfigArgsConfigSource;
import org.keycloak.quarkus.runtime.configuration.mappers.HttpPropertyMappers;
import org.keycloak.quarkus.runtime.Environment;
import org.keycloak.quarkus.runtime.vault.FilesKeystoreVaultProviderFactory;
import org.keycloak.quarkus.runtime.vault.FilesPlainTextVaultProviderFactory;
import org.mariadb.jdbc.MariaDbDataSource;
import org.postgresql.xa.PGXADataSource;

public class ConfigurationTest extends AbstractConfigurationTest {

    @Test
    public void testCamelCase() {
        putEnvVar("KC_SPI_CAMEL_CASE_SCOPE_CAMEL_CASE_PROP", "foobar");
        initConfig();
        String value = Config.scope("camelCaseScope").get("camelCaseProp");
        assertEquals(value, "foobar");
    }

    @Test
    public void testEnvVarPriorityOverPropertiesFile() {
        putEnvVar("KC_SPI_HOSTNAME_DEFAULT_FRONTEND_URL", "http://envvar.unittest");
        assertEquals("http://envvar.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testKeycloakConfPlaceholder() {
        assertEquals("info", createConfig().getRawValue("kc.log-level"));
        putEnvVar("SOME_LOG_LEVEL", "debug");
        assertEquals("debug", createConfig().getRawValue("kc.log-level"));
    }

    @Test
    public void testEnvVarAvailableFromPropertyNames() {
        putEnvVar("KC_VAULT_DIR", "/foo/bar");
        Config.Scope config = initConfig("vault", FilesPlainTextVaultProviderFactory.ID);
        assertEquals("/foo/bar", config.get("dir"));
        assertTrue(config.getPropertyNames()
                .contains("kc.spi-vault-".concat(FilesPlainTextVaultProviderFactory.ID).concat("-dir")));

        putEnvVar("KC_VAULT_TYPE", "JKS");
        config = initConfig("vault", FilesKeystoreVaultProviderFactory.ID);
        assertEquals("JKS", config.get("type"));
        assertTrue(config.getPropertyNames()
                .contains("kc.spi-vault-".concat(FilesKeystoreVaultProviderFactory.ID).concat("-type")));
    }

    @Test
    public void testEnvVarPriorityOverSysProps() {
        putEnvVar("KC_SPI_HOSTNAME_DEFAULT_FRONTEND_URL", "http://envvar.unittest");
        System.setProperty("kc.spi-hostname-default-frontend-url", "http://propvar.unittest");
        assertEquals("http://envvar.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testCLIPriorityOverSysProp() {
        System.setProperty("kc.spi.hostname.default.frontend-url", "http://propvar.unittest");
        ConfigArgsConfigSource.setCliArgs("--spi-hostname-default-frontend-url=http://cli.unittest");
        assertEquals("http://cli.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testDefaultValueFromProperty() {
        System.setProperty("keycloak.frontendUrl", "http://defaultvalueprop.unittest");
        assertEquals("http://defaultvalueprop.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testDefaultValue() {
        assertEquals("http://filepropdefault.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testKeycloakProfilePropertySubstitution() {
        System.setProperty(org.keycloak.common.util.Environment.PROFILE, "user-profile");
        assertEquals("http://filepropprofile.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testQuarkusProfilePropertyStillWorks() {
        System.setProperty("quarkus.profile", "user-profile");
        assertEquals("http://filepropprofile.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testCommandLineArguments() {
        ConfigArgsConfigSource.setCliArgs("--spi-hostname-default-frontend-url=http://fromargs.unittest", "--no-ssl");
        assertEquals("http://fromargs.unittest", initConfig("hostname", "default").get("frontendUrl"));
    }

    @Test
    public void testSpiConfigurationUsingCommandLineArguments() {
        ConfigArgsConfigSource.setCliArgs("--spi-hostname-default-frontend-url=http://spifull.unittest");
        assertEquals("http://spifull.unittest", initConfig("hostname", "default").get("frontendUrl"));

        // test multi-word SPI names using camel cases
        ConfigArgsConfigSource.setCliArgs("--spi-action-token-handler-verify-email-some-property=test");
        assertEquals("test", initConfig("action-token-handler", "verify-email").get("some-property"));
        ConfigArgsConfigSource.setCliArgs("--spi-action-token-handler-verify-email-some-property=test");
        assertEquals("test", initConfig("actionTokenHandler", "verifyEmail").get("someProperty"));

        // test multi-word SPI names using slashes
        ConfigArgsConfigSource.setCliArgs("--spi-client-registration-openid-connect-static-jwk-url=http://c.jwk.url");
        assertEquals("http://c.jwk.url", initConfig("client-registration", "openid-connect").get("static-jwk-url"));
    }

    @Test
    public void testResolveTransformedValue() {
        ConfigArgsConfigSource.setCliArgs("");
        assertEquals("false", createConfig().getConfigValue("kc.proxy-allow-forwarded-header").getValue());
        ConfigArgsConfigSource.setCliArgs("--proxy-headers=xforwarded");
        assertEquals("false", createConfig().getConfigValue("kc.proxy-allow-forwarded-header").getValue());
        ConfigArgsConfigSource.setCliArgs("--proxy-headers=forwarded");
        assertEquals("true", createConfig().getConfigValue("kc.proxy-allow-forwarded-header").getValue());
    }

    @Test
    public void testPropertyNamesFromConfig() {
        ConfigArgsConfigSource.setCliArgs("--spi-client-registration-openid-connect-static-jwk-url=http://c.jwk.url");
        Config.Scope config = initConfig("client-registration", "openid-connect");
        assertEquals(1, config.getPropertyNames().size());
        assertEquals("http://c.jwk.url", config.get("static-jwk-url"));

        ConfigArgsConfigSource.setCliArgs("--vault-dir=secrets");
        config = initConfig("vault", FilesPlainTextVaultProviderFactory.ID);
        assertEquals(1, config.getPropertyNames().size());
        assertEquals("secrets", config.get("dir"));

        ConfigArgsConfigSource.setCliArgs("--vault-type=JKS");
        config = initConfig("vault", FilesKeystoreVaultProviderFactory.ID);
        assertEquals(1, config.getPropertyNames().size());
        assertEquals("JKS", config.get("type"));

        ConfigArgsConfigSource.setCliArgs();
        System.setProperty("kc.spi-client-registration-openid-connect-static-jwk-url", "http://c.jwk.url");
        config = initConfig("client-registration", "openid-connect");
        assertEquals(1, config.getPropertyNames().size());
        assertEquals("http://c.jwk.url", config.get("static-jwk-url"));

        ConfigArgsConfigSource.setCliArgs();
        System.getProperties().remove("kc.spi-client-registration-openid-connect-static-jwk-url");
        putEnvVar("KC_SPI_CLIENT_REGISTRATION_OPENID_CONNECT_STATIC_JWK_URL", "http://c.jwk.url/from-env");
        config = initConfig("client-registration", "openid-connect");
        assertEquals(2, config.getPropertyNames().size()); // transformed name is coming from KcEnvVarConfigSource, raw env var name is coming from EnvVarConfigSource
        assertEquals("http://c.jwk.url/from-env", config.get("static-jwk-url"));
    }


    @Test
    public void testPropertyMapping() {
        ConfigArgsConfigSource.setCliArgs("--db=mariadb", "--db-url=jdbc:mariadb://localhost/keycloak");
        SmallRyeConfig config = createConfig();
        assertEquals(MariaDBDialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:mariadb://localhost/keycloak", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
    }

    @Test
    public void testDatabaseUrlProperties() {
        ConfigArgsConfigSource.setCliArgs("--db=mariadb", "--db-url=jdbc:mariadb:aurora://foo/bar?a=1&b=2");
        SmallRyeConfig config = createConfig();
        assertEquals(MariaDBDialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:mariadb:aurora://foo/bar?a=1&b=2", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
    }
    
    @Test
    public void testExpansionDisabled() {
        ConfigArgsConfigSource.setCliArgs("--db=mysql");
        SmallRyeConfig config = createConfig();
        String value = Expressions.withoutExpansion(() -> config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("jdbc:mysql://${kc.db-url-host:localhost}:${kc.db-url-port:3306}/${kc.db-url-database:keycloak}${kc.db-url-properties:}", value);
    }

    @Test
    public void testDatabaseDefaults() {
        ConfigArgsConfigSource.setCliArgs("--db=dev-file");
        SmallRyeConfig config = createConfig();
        assertEquals(H2Dialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals(Driver.class.getName(), config.getConfigValue("quarkus.datasource.jdbc.driver").getValue());

        // JDBC location treated as file:// URI
        final String userHomeUri = Path.of(System.getProperty("user.home"))
                .toUri()
                .toString()
                .replaceFirst(isWindows() ? "file:///" : "file://", "");

        assertEquals("jdbc:h2:file:" + userHomeUri + "data/h2/keycloakdb;NON_KEYWORDS=VALUE;DB_CLOSE_ON_EXIT=FALSE;DB_CLOSE_DELAY=0", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());

        ConfigArgsConfigSource.setCliArgs("--db=dev-mem");
        config = createConfig();
        assertEquals(H2Dialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:h2:mem:keycloakdb;NON_KEYWORDS=VALUE;DB_CLOSE_ON_EXIT=FALSE;DB_CLOSE_DELAY=0", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("h2", config.getConfigValue("quarkus.datasource.db-kind").getValue());

        ConfigArgsConfigSource.setCliArgs("--db=dev-mem", "--db-username=other");
        config = createConfig();
        assertEquals("sa", config.getConfigValue("quarkus.datasource.username").getValue());
        // should be untransformed
        assertEquals("other", config.getConfigValue("kc.db-username").getValue());

        ConfigArgsConfigSource.setCliArgs("--db=postgres", "--db-username=other");
        config = createConfig();
        assertEquals("other", config.getConfigValue("quarkus.datasource.username").getValue());

        ConfigArgsConfigSource.setCliArgs("--db=postgres");
        config = createConfig();
        // username should not be set, either as the quarkus or kc property
        assertEquals(null, config.getConfigValue("quarkus.datasource.username").getValue());
        assertEquals(null, config.getConfigValue("kc.db-username").getValue());
    }

    @Test
    public void testDatabaseKindProperties() {
        ConfigArgsConfigSource.setCliArgs("--db=postgres", "--db-url=jdbc:postgresql://localhost/keycloak", "--db-username=postgres");
        SmallRyeConfig config = createConfig();
        assertEquals("org.hibernate.dialect.PostgreSQLDialect",
            config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:postgresql://localhost/keycloak", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("postgresql", config.getConfigValue("quarkus.datasource.db-kind").getValue());
        assertEquals("postgres", config.getConfigValue("quarkus.datasource.username").getValue());
    }

    @Test
    public void testDefaultDbPropertiesGetApplied() {
        ConfigArgsConfigSource.setCliArgs("--db=postgres", "--db-url-host=myhost", "--db-url-database=kcdb", "--db-url-properties=?foo=bar");
        SmallRyeConfig config = createConfig();
        assertEquals("org.hibernate.dialect.PostgreSQLDialect",
                config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:postgresql://myhost:5432/kcdb?foo=bar", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("postgresql", config.getConfigValue("quarkus.datasource.db-kind").getValue());
    }

    @Test
    public void testRemoveSpaceFromValue() {
        ConfigArgsConfigSource.setCliArgs("--db=postgres      ");
        SmallRyeConfig config = createConfig();
        assertEquals("org.hibernate.dialect.PostgreSQLDialect",
                config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("postgres", config.getConfigValue("quarkus.datasource.db-kind").getRawValue());
    }

    @Test
    public void testDefaultDbPortGetApplied() {
        ConfigArgsConfigSource.setCliArgs("--db=mssql", "--db-url-host=myhost", "--db-url-database=kcdb", "--db-url-port=1234", "--db-url-properties=?foo=bar");
        SmallRyeConfig config = createConfig();
        assertEquals("org.hibernate.dialect.SQLServerDialect",
                config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:sqlserver://myhost:1234;databaseName=kcdb?foo=bar", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("mssql", config.getConfigValue("quarkus.datasource.db-kind").getValue());
    }

    @Test
    public void testSetDbUrlOverridesDefaultDataSource() {
        ConfigArgsConfigSource.setCliArgs("--db=mariadb", "--db-url-host=myhost", "--db-url=jdbc:mariadb://localhost/keycloak");
        SmallRyeConfig config = createConfig();
        assertEquals("org.hibernate.dialect.MariaDBDialect",
                config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:mariadb://localhost/keycloak", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("mariadb", config.getConfigValue("quarkus.datasource.db-kind").getValue());
    }

    @Test
    public void testDatabaseProperties() {
        System.setProperty("kc.db-url-properties", ";;test=test;test1=test1");
        System.setProperty("kc.db-url-path", "test-dir");
        System.setProperty("kc.transaction-xa-enabled", "true");
        ConfigArgsConfigSource.setCliArgs("--db=dev-file");
        SmallRyeConfig config = createConfig();
        assertEquals(H2Dialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:h2:file:test-dir/data/h2/keycloakdb;;test=test;test1=test1;NON_KEYWORDS=VALUE;DB_CLOSE_ON_EXIT=FALSE;DB_CLOSE_DELAY=0", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("xa", config.getConfigValue("quarkus.datasource.jdbc.transactions").getValue());

        ConfigArgsConfigSource.setCliArgs("");
        config = createConfig();
        assertEquals(H2Dialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals("jdbc:h2:file:test-dir/data/h2/keycloakdb;;test=test;test1=test1;NON_KEYWORDS=VALUE;DB_CLOSE_ON_EXIT=FALSE;DB_CLOSE_DELAY=0", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());

        System.setProperty("kc.db-url-properties", "?test=test&test1=test1");
        ConfigArgsConfigSource.setCliArgs("--db=mariadb");
        config = createConfig();
        assertEquals("jdbc:mariadb://localhost:3306/keycloak?test=test&test1=test1", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals(MariaDBDialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals(MariaDbDataSource.class.getName(), config.getConfigValue("quarkus.datasource.jdbc.driver").getValue());

        ConfigArgsConfigSource.setCliArgs("--db=postgres");
        config = createConfig();
        assertEquals("jdbc:postgresql://localhost:5432/keycloak?test=test&test1=test1", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals(PostgreSQLDialect.class.getName(), config.getConfigValue("kc.db-dialect").getValue());
        assertEquals(PGXADataSource.class.getName(), config.getConfigValue("quarkus.datasource.jdbc.driver").getValue());

        ConfigArgsConfigSource.setCliArgs("--db-schema=test-schema");
        config = createConfig();
        assertEquals("test-schema", config.getConfigValue("kc.db-schema").getValue());
        assertEquals("test-schema", config.getConfigValue("kc.db-schema").getValue());
    }

    // KEYCLOAK-15632
    @Test
    public void testNestedDatabaseProperties() {
        System.setProperty("kc.home.dir", "/tmp/kc/bin/../");
        SmallRyeConfig config = createConfig();
        assertEquals("jdbc:h2:file:/tmp/kc/bin/..//data/keycloakdb", config.getConfigValue("quarkus.datasource.foo").getValue());

        Assert.assertEquals("foo-def-suffix", config.getConfigValue("quarkus.datasource.bar").getValue());

        System.setProperty("kc.prop5", "val5");
        config = createConfig();
        Assert.assertEquals("foo-val5-suffix", config.getConfigValue("quarkus.datasource.bar").getValue());

        System.setProperty("kc.prop4", "val4");
        config = createConfig();
        Assert.assertEquals("foo-val4", config.getConfigValue("quarkus.datasource.bar").getValue());

        System.setProperty("kc.prop3", "val3");
        config = createConfig();
        Assert.assertEquals("foo-val3", config.getConfigValue("quarkus.datasource.bar").getValue());
    }

    @Test
    public void testClusterConfig() {
        // Cluster enabled by default, but disabled for the "dev" profile
        Assert.assertEquals("cache-ispn.xml", initConfig("connectionsInfinispan", "quarkus").get("configFile"));

        // If explicitly set, then it is always used regardless of the profile
        System.clearProperty(org.keycloak.common.util.Environment.PROFILE);
        ConfigArgsConfigSource.setCliArgs("--cache-config-file=cluster-foo.xml");

        Assert.assertEquals("cluster-foo.xml", initConfig("connectionsInfinispan", "quarkus").get("configFile"));
        System.setProperty(org.keycloak.common.util.Environment.PROFILE, "dev");
        Assert.assertEquals("cluster-foo.xml", initConfig("connectionsInfinispan", "quarkus").get("configFile"));

        ConfigArgsConfigSource.setCliArgs("--cache-stack=foo");
        Assert.assertEquals("foo", initConfig("connectionsInfinispan", "quarkus").get("stack"));
    }

    @Test
    public void testCommaSeparatedArgValues() {
        ConfigArgsConfigSource.setCliArgs("--spi-client-jpa-searchable-attributes=bar,foo");
        assertEquals("bar,foo", initConfig("client-jpa").get("searchable-attributes"));

        ConfigArgsConfigSource.setCliArgs("--spi-client-jpa-searchable-attributes=bar,foo,foo bar");
        assertEquals("bar,foo,foo bar", initConfig("client-jpa").get("searchable-attributes"));

        ConfigArgsConfigSource.setCliArgs("--spi-client-jpa-searchable-attributes=bar,foo, \"foo bar\"");
        assertEquals("bar,foo, \"foo bar\"", initConfig("client-jpa").get("searchable-attributes"));

        ConfigArgsConfigSource.setCliArgs("--spi-client-jpa-searchable-attributes=bar,foo, \"foo bar\"", "--spi-hostname-default-frontend-url=http://foo.unittest");
        assertEquals("http://foo.unittest", initConfig("hostname-default").get("frontend-url"));
    }

    @Test
    public void testDatabaseDriverSetExplicitly() {
        ConfigArgsConfigSource.setCliArgs("--db=mssql", "--db-url=jdbc:sqlserver://localhost/keycloak");
        System.setProperty("kc.db-driver", "com.microsoft.sqlserver.jdbc.SQLServerDriver");
        System.setProperty("kc.transaction-xa-enabled", "false");
        assertTrue(ConfigArgsConfigSource.getAllCliArgs().contains("--db=mssql"));
        SmallRyeConfig config = createConfig();
        assertEquals("jdbc:sqlserver://localhost/keycloak", config.getConfigValue("quarkus.datasource.jdbc.url").getValue());
        assertEquals("mssql", config.getConfigValue("quarkus.datasource.db-kind").getValue());
        assertEquals("com.microsoft.sqlserver.jdbc.SQLServerDriver", config.getConfigValue("quarkus.datasource.jdbc.driver").getValue());
        assertEquals("enabled", config.getConfigValue("quarkus.datasource.jdbc.transactions").getValue());
    }

    @Test
    public void testDatabaseDialectSetExplicitly() {
        ConfigArgsConfigSource.setCliArgs("--db-dialect=user-defined");
        assertEquals("user-defined", createConfig().getRawValue("kc.db-dialect"));
    }

    @Test
    public void testTransactionTypeChangesDriver() {
        ConfigArgsConfigSource.setCliArgs("--db=mssql", "--transaction-xa-enabled=false");
        assertTrue(ConfigArgsConfigSource.getAllCliArgs().contains("--db=mssql"));

        SmallRyeConfig jtaEnabledConfig = createConfig();
        assertEquals("com.microsoft.sqlserver.jdbc.SQLServerDriver", jtaEnabledConfig.getConfigValue("quarkus.datasource.jdbc.driver").getValue());
        assertEquals("enabled", jtaEnabledConfig.getConfigValue("quarkus.datasource.jdbc.transactions").getValue());

        ConfigArgsConfigSource.setCliArgs("--db=mssql", "--transaction-xa-enabled=true");
        assertTrue(ConfigArgsConfigSource.getAllCliArgs().contains("--db=mssql"));
        SmallRyeConfig xaConfig = createConfig();

        assertEquals("com.microsoft.sqlserver.jdbc.SQLServerXADataSource", xaConfig.getConfigValue("quarkus.datasource.jdbc.driver").getValue());
        assertEquals("xa", xaConfig.getConfigValue("quarkus.datasource.jdbc.transactions").getValue());
    }

    @Test
    public void testResolveHealthOption() {
        ConfigArgsConfigSource.setCliArgs("--health-enabled=true");
        SmallRyeConfig config = createConfig();
        assertEquals("true", config.getConfigValue("quarkus.smallrye-health.extensions.enabled").getValue());
        ConfigArgsConfigSource.setCliArgs("");
        config = createConfig();
        assertEquals("false", config.getConfigValue("quarkus.smallrye-health.extensions.enabled").getValue());
    }

    @Test
    public void testResolveMetricsOption() {
        ConfigArgsConfigSource.setCliArgs("--metrics-enabled=true");
        SmallRyeConfig config = createConfig();
        assertEquals("true", config.getConfigValue("quarkus.datasource.metrics.enabled").getValue());
    }

    @Test
    public void testOptionValueWithEqualSign() {
        ConfigArgsConfigSource.setCliArgs("--db=postgres", "--db-password=my_secret=");
        SmallRyeConfig config = createConfig();
        assertEquals("my_secret=", config.getConfigValue("kc.db-password").getValue());
    }

    @Test
    public void testResolvePropertyFromDefaultProfile() {
        Environment.setProfile(Environment.NON_SERVER_MODE);
        assertEquals("false", createConfig().getConfigValue("kc.hostname-strict").getValue());

        Environment.setProfile("prod");
        assertEquals("true", createConfig().getConfigValue("kc.spi-hostname-v2-hostname-strict").getValue());
    }

    @Test
    public void testKeystoreConfigSource() {
        // Add properties manually
        Map<String, String> properties = new HashMap<>();
        properties.put("smallrye.config.source.keystore.kc-default.path", "keystore");
        properties.put("smallrye.config.source.keystore.kc-default.password", "secret");

        SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDefaultInterceptors()
                .addDiscoveredSources()
                .withSources(new PropertiesConfigSource(properties, "", 0))
                .build();

        ConfigValue secret = config.getConfigValue("my.secret");
        assertEquals("secret", secret.getValue());
    }

    @Test
    public void testKeystoreConfigSourcePropertyMapping() {
        SmallRyeConfig config = new SmallRyeConfigBuilder()
                .addDefaultInterceptors()
                .addDiscoveredSources()
                .build();

        assertEquals(config.getConfigValue("smallrye.config.source.keystore.kc-default.password").getValue(),config.getConfigValue("kc.config-keystore-password").getValue());
        // Properties are loaded from the file - secret can be obtained only if the mapping works correctly
        ConfigValue secret = config.getConfigValue("my.secret");
        assertEquals("secret", secret.getValue());
    }

    @Test
    public void testReloadPeriod() {
        ConfigArgsConfigSource.setCliArgs("");
        assertEquals("1h", createConfig().getConfigValue("quarkus.http.ssl.certificate.reload-period").getValue());
        ConfigArgsConfigSource.setCliArgs("--https-certificates-reload-period=-1");
        assertNull(createConfig().getConfigValue("quarkus.http.ssl.certificate.reload-period").getValue());
        ConfigArgsConfigSource.setCliArgs("--https-certificates-reload-period=2h");
        assertEquals("2h", createConfig().getConfigValue("quarkus.http.ssl.certificate.reload-period").getValue());
    }

    @Test
    public void testHttpsPaths() {
        ConfigArgsConfigSource.setCliArgs("--https-certificate-file=\\some\\file");

        String expected = "\\some\\file";
        if (FileSystems.getDefault().getSeparator().equals("\\")) {
            expected = "/some/file";
        }
        assertEquals(expected, createConfig().getConfigValue("quarkus.http.ssl.certificate.files").getValue());
    }

    @Test
    public void testHttpTrustStoreType() {
        ConfigArgsConfigSource.setCliArgs("--fips-mode=strict");
        assertEquals("BCFKS", createConfig().getConfigValue(HttpPropertyMappers.QUARKUS_HTTPS_TRUST_STORE_FILE_TYPE).getValue());

        ConfigArgsConfigSource.setCliArgs("--https-trust-store-type=jks");
        assertEquals("jks", createConfig().getConfigValue(HttpPropertyMappers.QUARKUS_HTTPS_TRUST_STORE_FILE_TYPE).getValue());
    }

    @Test
    public void testCacheMaxCount() {
        int maxCount = 500;
        Set<String> maxCountCaches = Stream.of(CachingOptions.LOCAL_MAX_COUNT_CACHES, CachingOptions.CLUSTERED_MAX_COUNT_CACHES)
              .flatMap(Arrays::stream)
              .collect(Collectors.toSet());

        StringBuilder sb = new StringBuilder();
        for (String cache : maxCountCaches)
            sb.append(" --").append(CachingOptions.cacheMaxCountProperty(cache)).append("=").append(maxCount);

        String args = sb.toString();
        ConfigArgsConfigSource.setCliArgs(args.split(" "));
        SmallRyeConfig config = createConfig();

        for (String cache : maxCountCaches) {
            String prop = "kc." + CachingOptions.cacheMaxCountProperty(cache);
            assertEquals(Integer.toString(maxCount), config.getConfigValue(prop).getValue());
        }
    }
}
