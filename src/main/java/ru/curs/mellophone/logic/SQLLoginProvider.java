package ru.curs.mellophone.logic;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static java.lang.Math.min;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;


/**
 * Конфигурация подключения к SQL-серверу.
 */
public final class SQLLoginProvider extends AbstractLoginProvider {

    private static final String USER = "Пользователь '";
    private static final String USER_LOGIN = "Логин пользователя '";
    private static final String ERROR_SQL_SERVER = "Ошибка при работе с базой '%s': %s. Запрос: '%s'";

    private static final String USER_IS_BLOCKED_PERMANENTLY = "User %s is blocked permanently.";

    private static final String PASSWORD_DIVIDER = "#";

    private static final String PBKDF2 = "pbkdf2";
    private static final String PBKDF2_PASSWORD_DIVIDER = "\\$";
    private static final String PBKDF2_ALG_DIVIDER = ":";

    private static final ConcurrentHashMap<String, MessageDigest> mdPool = new ConcurrentHashMap<>(4);
    private final HashMap<String, String> searchReturningAttributes = new HashMap<>();
    private final Properties hikariProperties = new Properties();
    private JdbcTemplate jdbcTemplate;
    private String connectionUsername;
    private String connectionPassword;
    private String table;
    private String fieldLogin;
    private String fieldPassword;
    private String fieldBlocked = null;
    private String hashAlgorithm = "SHA-256";
    private String localSecuritySalt = "";
    private String procPostProcess = null;

    private static void checkForPossibleSQLInjection(String sql, String errMsg) throws EAuthServerLogic {
        if (sql.contains(" ")) throw EAuthServerLogic.create(errMsg);
    }

    @Override
    void setupLogger(boolean isLogging) {
        if (isLogging) {
            setLogger(LoggerFactory.getLogger(SQLLoginProvider.class));
        }
    }

    void addHikariProperty(String name, String value) {
        hikariProperties.put(name, value);
    }

    void setConnectionUsername(String connectionUsername) {
        this.connectionUsername = connectionUsername;
    }

    void setConnectionPassword(String connectionPassword) {
        this.connectionPassword = connectionPassword;
    }

    void setTable(String table) {
        this.table = table.replace(".", "\".\"");
    }

    void setFieldLogin(String fieldLogin) {
        this.fieldLogin = fieldLogin;
    }

    void setFieldPassword(String fieldPassword) {
        this.fieldPassword = fieldPassword;
    }

    void setFieldBlocked(String fieldBlocked) {
        this.fieldBlocked = fieldBlocked;
    }

    void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    void setLocalSecuritySalt(String localSecuritySalt) {
        this.localSecuritySalt = localSecuritySalt;
    }

    void setProcPostProcess(String procPostProcess) {
        this.procPostProcess = procPostProcess;
    }

    @Override
    void addReturningAttributes(String name, String value) {
        searchReturningAttributes.put(name, value);
    }

    @Override
    public void initialize() {
        HikariConfig hikariConfig = new HikariConfig(hikariProperties);
        if (nonNull(getConnectionUrl())) {
            hikariConfig.setJdbcUrl(getConnectionUrl());
        }
        if (nonNull(connectionUsername)) {
            hikariConfig.setUsername(connectionUsername);
        }
        if (isNull(hikariConfig.getDataSourceClassName()) && nonNull(connectionPassword)) {
            hikariConfig.setPassword(connectionPassword);
        }
        HikariDataSource dataSource = new HikariDataSource(hikariConfig);
        jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    void connect(String sesid, String login, String password, String ip, ProviderContextHolder context, PrintWriter pw) throws EAuthServerLogic {

        if (nonNull(getLogger())) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("login='" + login + "'");
        }

        checkForPossibleSQLInjection(login, USER_LOGIN + login + "' в '" + getConnectionUrl() + "' не успешен");

        boolean success = false;
        String message = "";
        String sql = "";
        BadLoginType blt = BadLoginType.BAD_CREDENTIALS;
        try {
            sql = String.format("SELECT \"%s\", %s FROM \"%s\" WHERE \"%s\" = ?", fieldPassword, getSelectFields(),
                    table, fieldLogin);
            List<Credentials> credentials = jdbcTemplate.query(sql, new SQLLoginProvider.CredentialsRowMapper(), login);
            if (credentials.size() == 1) {

                if (isNull(procPostProcess) && nonNull(fieldBlocked)) {
                    if (credentials.get(0).isBlocked()) {
                        message = String.format(USER_IS_BLOCKED_PERMANENTLY, login);
                        blt = BadLoginType.USER_BLOCKED_PERMANENTLY;
                    }
                }

                if (blt != BadLoginType.USER_BLOCKED_PERMANENTLY) {

                    String pwdComplex = credentials.get(0).getPwd();
                    success = nonNull(pwdComplex)
                            &&
                            (
                                    (!AuthManager.getTheManager().isCheckPasswordHashOnly())
                                            && pwdComplex.equals(password)
                                            || checkPasswordHash(pwdComplex, password)
                            );

                    StringWriter sw = new StringWriter();
                    XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(sw);
                    xw.writeStartDocument("utf-8", "1.0");
                    xw.writeEmptyElement("user");
                    String[] attrs = credentials.get(0).getUserAttrs().keySet().toArray(new String[0]);
                    for (String attr : attrs) {
                        writeXMLAttr(xw, attr, credentials.get(0).getUserAttrs().get(attr));
                    }
                    xw.writeEndDocument();
                    xw.flush();
                    sw.flush();

                    if (nonNull(procPostProcess)) {
                        PostProcessResult ppr = callProcPostProcess(sesid, login, success, sw.toString(), ip, false,
                                LockoutManager.getLockoutManager().getAttemptsCount(login) + 1,
                                LockoutManager.getLockoutTime() * 60);
                        success = success && ppr.isSuccess();
                        message = ppr.getMessage();
                    } else {
                        if (success) {
                            message = USER_LOGIN + login + "' в '" + getConnectionUrl() + "' успешен!";
                        }
                    }

                    if (success && nonNull(pw)) {
                        pw.append(sw.toString());
                    }
                }

            } else {
                if (nonNull(procPostProcess)) {
                    PostProcessResult ppr = callProcPostProcess(sesid, login, false, null, ip,
                            false, LockoutManager.getLockoutManager().getAttemptsCount(login) + 1,
                            LockoutManager.getLockoutTime() * 60);
                    message = ppr.getMessage();
                }
            }
        } catch (Exception e) {
            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

        if (!success && message.isEmpty()) {
            message = USER_LOGIN + login + "' в '" + getConnectionUrl() + "' не успешен: " + BAD_CREDENTIALS;
        }

        if (nonNull(getLogger())) {
            getLogger().info(message);
        }

        if (!success) {
            EAuthServerLogic eas = EAuthServerLogic.create(message);
            eas.setBadLoginType(blt);
            throw eas;
        }

    }

    public PostProcessResult callProcPostProcess(String sesid, String login, boolean isauth, String attributes, String ip, boolean islocked, int attemptsCount, long timeToUnlock) {

        SimpleJdbcCall simpleJdbcCall = new SimpleJdbcCall(jdbcTemplate).withProcedureName(procPostProcess)
                .declareParameters(new SqlOutParameter("ret", Types.INTEGER),
                        new SqlOutParameter("message", Types.VARCHAR));

        SqlParameterSource in = new MapSqlParameterSource().addValue("sesid", sesid).addValue("userlogin", login)
                .addValue("userauth", isauth).addValue("userattributes", attributes).addValue("userip", ip)
                .addValue("userlocked", islocked).addValue("userloginattempts", attemptsCount)
                .addValue("usertimetounlock", timeToUnlock);

        Map<String, Object> out = simpleJdbcCall.execute(in);

        return new PostProcessResult(((int) out.get("ret")) == 0,
                "Stored procedure message begin: " + out.get("message") + " Stored procedure message end.");

    }


    private boolean checkPasswordHash(String pwdComplex, String password) throws EAuthServerLogic {

        if (PBKDF2.equalsIgnoreCase(pwdComplex.substring(0, min(pwdComplex.length(), PBKDF2.length())))) {
            String[] pwdParts = pwdComplex.split(PBKDF2_PASSWORD_DIVIDER);

            String alg = pwdParts[0];
            String salt = pwdParts[1];
            String hash = pwdParts[2];

            String[] algParts = alg.split(PBKDF2_ALG_DIVIDER);

            int iterations = Integer.parseInt(algParts[2]);

            return hash.equals(getHashForPBKDF2(password, salt, iterations));

        } else {
            String alg;
            String salt;
            String hash;

            String[] pwdParts = pwdComplex.split(PASSWORD_DIVIDER);
            if (pwdParts.length >= 3) {
                alg = getHashAlgorithm2(pwdParts[0]);
                salt = pwdParts[1];
                hash = pwdParts[2];
            } else {
                alg = "SHA-1";
                salt = "";
                hash = pwdComplex;
            }

            return hash.equals(getHash(password + salt + localSecuritySalt, alg));
        }

    }

    private String getSelectFields() {
        String[] fields = searchReturningAttributes.values().toArray(new String[0]);

        StringBuilder s = null;
        for (String field : fields) {
            field = String.format("\"%s\"", field);
            if (isNull(s)) {
                s = new StringBuilder(field);
            } else {
                if (s.toString().contains(field)) {
                    continue;
                }
                s.append(", ").append(field);
            }
        }

        if (nonNull(fieldBlocked)) {
            String field = String.format("\"%s\"", fieldBlocked);
            if (isNull(s)) {
                s = new StringBuilder(field);
            } else {
                s.append(", ").append(field);
            }
        }

        return isNull(s) ? null : s.toString();
    }

    @Override
    void getUserInfoByName(ProviderContextHolder context, String name, PrintWriter pw) throws EAuthServerLogic {

        if (nonNull(getLogger())) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("name='" + name + "'");
        }

        checkForPossibleSQLInjection(name, USER + name + "' не найден");

        String sql = "";
        try {
            String query = String.format("SELECT %s FROM \"%s\" WHERE \"%s\" = ?", getSelectFields(),
                    table, fieldLogin);
            List<SQLLoginProvider.UserInfo> uis = jdbcTemplate.query(query, new SQLLoginProvider.UserInfoRowMapper(),
                    name);

            if (uis.size() == 1) {
                XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
                xw.writeStartDocument("utf-8", "1.0");
                xw.writeEmptyElement("user");
                String[] attrs = uis.get(0).getUserAttrs().keySet().toArray(new String[0]);
                for (String attr : attrs) {
                    writeXMLAttr(xw, attr, uis.get(0).getUserAttrs().get(attr));
                }
                xw.writeEndDocument();
                xw.flush();

                return;
            }

            if (nonNull(getLogger())) {
                getLogger().info(USER + name + "' не найден");
            }

        } catch (Exception e) {
            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }
    }

    @Override
    void importUsers(ProviderContextHolder context, PrintWriter pw, boolean needStartDocument) throws EAuthServerLogic {

        if (nonNull(getLogger())) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
        }

        String sql = "";
        try {
            XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
            if (needStartDocument) {
                xw.writeStartDocument("utf-8", "1.0");
            }
            xw.writeStartElement("users");
            writeXMLAttr(xw, "pid", getId());

            sql = String.format("SELECT %s FROM \"%s\" ORDER BY \"%s\"", getSelectFields(), table, fieldLogin);
            List<SQLLoginProvider.UserInfo> uis = jdbcTemplate.query(sql, new SQLLoginProvider.UserInfoRowMapper());

            for (SQLLoginProvider.UserInfo ui : uis) {
                xw.writeEmptyElement("user");
                String[] attrs = ui.getUserAttrs().keySet().toArray(new String[0]);
                for (String attr : attrs) {
                    writeXMLAttr(xw, attr, ui.getUserAttrs().get(attr));
                }
            }

            xw.writeEndDocument();
            xw.flush();

            if (nonNull(getLogger())) {
                getLogger().info("Импорт пользователей успешно завершен");
            }

        } catch (Exception e) {
            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }
    }

    @Override
    void changePwd(ProviderContextHolder context, String userName, String newpwd) throws EAuthServerLogic {

        if (nonNull(getLogger())) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("name='" + userName + "'");
        }

        checkForPossibleSQLInjection(userName, USER + userName + "' не найден");

        String sql = "";
        try {
            SecureRandom r = new SecureRandom();
            String salt = String.format("%016x", r.nextLong()) + String.format("%016x", r.nextLong());
            String password = getHashAlgorithm1(hashAlgorithm) + PASSWORD_DIVIDER + salt + PASSWORD_DIVIDER
                    + getHash(newpwd + salt + localSecuritySalt, hashAlgorithm);

            sql = String.format("UPDATE \"%s\" SET \"%s\" = ? WHERE \"%s\" = ?", table, fieldPassword, fieldLogin);
            jdbcTemplate.update(sql, password, userName);
        } catch (Exception e) {
            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

    }

    @Override
    ProviderContextHolder newContextHolder() {
        return new SQLLink();
    }

    /**
     * Возвращает значение функции SHA-1 для строки символов в виде 16-ричного
     * числа, в точности как реализовано в клиентском JavaScript. Необходимо для
     * контроля логинов и паролей
     */
    private String getHash(String input, String alg) throws EAuthServerLogic {

        MessageDigest md = mdPool.get(alg);
        if (isNull(md)) {
            try {
                md = MessageDigest.getInstance(alg);
                mdPool.putIfAbsent(alg, md);
            } catch (NoSuchAlgorithmException e) {
                if (nonNull(getLogger())) {
                    getLogger().error(e.getMessage());
                }
                throw EAuthServerLogic.create("Алгоритм хеширования " + alg + " не доступен");
            }
        }

        md.reset();
        md.update(input.getBytes(StandardCharsets.UTF_8));
        return asHex(md.digest());

    }

    private String getHashForPBKDF2(String password, String salt, int iterations) throws EAuthServerLogic {
        final int keyLength = 256;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] hashedBytes = key.getEncoded();
            HexFormat commaFormat = HexFormat.of();
            return commaFormat.formatHex(hashedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw EAuthServerLogic.create(e);
        }
    }

    private String getHashAlgorithm1(String input) {
        return input.toLowerCase().replace("-", "");
    }

    private String getHashAlgorithm2(String input) {
        return input.toUpperCase().replace("SHA", "SHA-");
    }


    private static class Credentials {
        private final HashMap<String, String> userAttrs = new HashMap<>();
        private String login;
        private String pwd;
        private boolean blocked = false;

        public String getLogin() {
            return login;
        }

        public void setLogin(String login) {
            this.login = login;
        }

        public String getPwd() {
            return pwd;
        }

        public void setPwd(String pwd) {
            this.pwd = pwd;
        }

        public boolean isBlocked() {
            return blocked;
        }

        public void setBlocked(boolean blocked) {
            this.blocked = blocked;
        }

        public HashMap<String, String> getUserAttrs() {
            return userAttrs;
        }
    }

    private static class UserInfo {
        private final HashMap<String, String> userAttrs = new HashMap<>();

        public HashMap<String, String> getUserAttrs() {
            return userAttrs;
        }
    }

    /**
     * Контекст соединения с базой данных.
     */
    private static class SQLLink extends ProviderContextHolder {
        @Override
        void closeContext() {
        }
    }

    private class CredentialsRowMapper implements RowMapper<SQLLoginProvider.Credentials> {
        @Override
        public SQLLoginProvider.Credentials mapRow(ResultSet rs, int rowNum) throws SQLException {
            SQLLoginProvider.Credentials credentials = new Credentials();
            credentials.setLogin(rs.getString(fieldLogin));
            credentials.setPwd(rs.getString(fieldPassword));
            if (nonNull(fieldBlocked)) {
                credentials.setBlocked(rs.getBoolean(fieldBlocked));
            }
            String[] attrs = searchReturningAttributes.keySet().toArray(new String[0]);
            for (String attr : attrs) {
                credentials.getUserAttrs().put(attr, rs.getString(searchReturningAttributes.get(attr)));
            }
            return credentials;
        }
    }

    private class UserInfoRowMapper implements RowMapper<SQLLoginProvider.UserInfo> {
        @Override
        public SQLLoginProvider.UserInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
            SQLLoginProvider.UserInfo ui = new UserInfo();
            String[] attrs = searchReturningAttributes.keySet().toArray(new String[0]);
            for (String attr : attrs) {
                ui.getUserAttrs().put(attr, rs.getString(searchReturningAttributes.get(attr)));
            }
            return ui;
        }
    }


}
