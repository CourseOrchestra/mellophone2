package ru.curs.mellophone.logic;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
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
public final class SQLExtLoginProvider extends AbstractLoginProvider {

    private static final String USER = "Пользователь '";
    private static final String USER_LOGIN = "Логин пользователя '";
    private static final String ERROR_SQL_SERVER = "Ошибка при работе с базой '%s': %s. Запрос: '%s'";

    private static final String PASSWORD_DIVIDER = "#";

    private static final String PBKDF2 = "pbkdf2";
    private static final String PBKDF2_PASSWORD_DIVIDER = "\\$";
    private static final String PBKDF2_ALG_DIVIDER = ":";

    private static final ConcurrentHashMap<String, MessageDigest> mdPool = new ConcurrentHashMap<>(4);
    private final Properties hikariProperties = new Properties();
    private JdbcTemplate jdbcTemplate;
    private DataSourceTransactionManager dataSourceTransactionManager;
    private String connectionUsername;
    private String connectionPassword;
    private String table = null;
    private String tableAttr;
    private String hashAlgorithm = "SHA-256";
    private String localSecuritySalt = "";
    private String procPostProcess = null;

    private static void checkForPossibleSQLInjection(String sql, String errMsg) throws EAuthServerLogic {
        if (sql.contains(" ")) throw EAuthServerLogic.create(errMsg);
    }

    @Override
    void setupLogger(boolean isLogging) {
        if (isLogging) {
            setLogger(LoggerFactory.getLogger(SQLExtLoginProvider.class));
        }
    }

    @Override
    void addReturningAttributes(String name, String value) {

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

    void setTableAttr(String tableAttr) {
        this.tableAttr = tableAttr.replace(".", "\".\"");
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
        dataSourceTransactionManager = new DataSourceTransactionManager(dataSource);
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
            String query = String.format("SELECT sid, login, pwd FROM \"%s\" WHERE \"login\" = ?", table);
            List<Credentials> credentials = jdbcTemplate.query(query, new CredentialsRowMapper(), login);
            if (credentials.size() == 1) {
                String pwdComplex = credentials.get(0).getPwd();
                success = nonNull(pwdComplex)
                        &&
                        (
                                (!AuthManager.getTheManager().isCheckPasswordHashOnly())
                                        && pwdComplex.equals(password)
                                        || checkPasswordHash(pwdComplex, password)
                        );

                StringWriter sw = new StringWriter();
                writeReturningAttributes(credentials.get(0), sw);
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

            } else {
                if (nonNull(procPostProcess)) {
                    PostProcessResult ppr = callProcPostProcess(sesid, login, false, null, ip, false,
                            LockoutManager.getLockoutManager().getAttemptsCount(login) + 1,
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

    private void writeReturningAttributes(Credentials credentials, Writer writer) throws XMLStreamException {
        String sid = credentials.getSid();
        String login = credentials.getLogin();

        XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(writer);
        xw.writeStartDocument("utf-8", "1.0");
        xw.writeEmptyElement("user");

        writeXMLAttr(xw, "sid", sid);
        writeXMLAttr(xw, "login", login);

        String sql = String.format("SELECT * FROM \"%s\" WHERE \"sid\" = ?", tableAttr);
        List<Attrs> attrs = jdbcTemplate.query(sql, new AttrsRowMapper(), sid);

        attrs.forEach(attr -> {
            try {
                writeXMLAttr(xw, attr.getFieldid(), attr.getFieldvalue());
            } catch (XMLStreamException e) {
                e.printStackTrace();
                throw EAuthServerLogic.create(e);
            }
        });

        xw.writeEndDocument();
        xw.flush();
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

    @Override
    void getUserInfoByName(ProviderContextHolder context, String name, PrintWriter pw) throws EAuthServerLogic {

        if (nonNull(getLogger())) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("name='" + name + "'");
        }

        checkForPossibleSQLInjection(name, USER + name + "' не найден");

        String sql = "";
        try {
            String query = String.format("SELECT sid, login, null as pwd FROM \"%s\" WHERE \"login\" = ?", table);
            List<Credentials> credentials = jdbcTemplate.query(query, new CredentialsRowMapper(), name);

            if (credentials.size() == 1) {
                StringWriter sw = new StringWriter();
                writeReturningAttributes(credentials.get(0), sw);
                sw.flush();
                pw.append(sw.toString());

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

            sql = String.format("UPDATE \"%s\" SET \"%s\" = ? WHERE \"%s\" = ?", table, "pwd", "login");
            jdbcTemplate.update(sql, password, userName);
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

            sql = String.format(
                    "SELECT a.sid, a.login, b.fieldid, b.fieldvalue FROM \"%s\" a LEFT OUTER JOIN \"%s\" b ON a.sid = b.sid ORDER BY a.sid",
                    table, tableAttr);
            List<AttrsExt> attrs = jdbcTemplate.query(sql, new AttrsExtRowMapper());

            String sid = "";
            for (AttrsExt attr : attrs) {
                if (!sid.equals(attr.getSid())) {
                    xw.writeEmptyElement("user");
                    writeXMLAttr(xw, "sid", attr.getSid());
                    writeXMLAttr(xw, "login", attr.getLogin());
                    sid = attr.getSid();
                }
                if (nonNull(attr.getFieldid())) {
                    writeXMLAttr(xw, attr.getFieldid(), attr.getFieldvalue());
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
    ProviderContextHolder newContextHolder() {
        return new SQLLink();
    }

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

    private Map<String, String> getUserAttrs(InputStream user) throws EAuthServerLogic {
        class UserParser extends DefaultHandler {
            final Map<String, String> out = new HashMap<>();

            @Override
            public void startElement(String uri, String localName, String qName, Attributes attributes) {
                for (int i = 0; i < attributes.getLength(); i++) {
                    out.put(attributes.getQName(i), attributes.getValue(i));
                }
            }
        }

        UserParser p = new UserParser();
        try {
            SaxonTransformerFactory.newInstance().newTransformer().transform(new StreamSource(user), new SAXResult(p));
        } catch (Exception e) {
            throw EAuthServerLogic.create(e);
        }

        return p.out;
    }


    public void userCreate(InputStream user) throws EAuthServerLogic {
        Map<String, String> attrsAll = getUserAttrs(user);

        String sid = null;
        String login = null;
        String pwd = null;
        Map<String, String> attrs = new HashMap<>();

        for (Map.Entry<String, String> pair : attrsAll.entrySet()) {
            String key = pair.getKey();
            String value = pair.getValue();
            if ("sid".equalsIgnoreCase(key)) {
                sid = value;
                continue;
            }
            if ("login".equalsIgnoreCase(key)) {
                login = value;
                continue;
            }
            if ("pwd".equalsIgnoreCase(key)) {
                pwd = value;
                continue;
            }

            attrs.put(key, value);
        }

        if (isNull(sid)) {
            throw EAuthServerLogic.create("Атрибут пользователя sid не задан");
        }


        String sql = null;
        TransactionStatus ts = dataSourceTransactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            String fields = "sid" + (nonNull(login) ? ", login" : "") + (nonNull(pwd) ? ", pwd" : "");
            String values = ":sid" + (nonNull(login) ? ", :login" : "") + (nonNull(pwd) ? ", :pwd" : "");
            sql = "INSERT INTO \"" + table + "\" (" + fields + ") VALUES (" + values + ")";
            MapSqlParameterSource in = new MapSqlParameterSource();
            in.addValue("sid", sid, Types.VARCHAR);
            if (nonNull(login)) {
                in.addValue("login", login, Types.VARCHAR);
            }
            if (nonNull(pwd)) {
                in.addValue("pwd", pwd, Types.VARCHAR);
            }
            (new NamedParameterJdbcTemplate(jdbcTemplate)).update(sql, in);

            String finalSid = sid;
            attrs.forEach((k, v) -> jdbcTemplate.update(
                    "INSERT INTO \"" + tableAttr + "\" (sid, fieldid, fieldvalue) VALUES (?, ?, ?)", finalSid, k, v));

            dataSourceTransactionManager.commit(ts);
        } catch (Exception e) {
            dataSourceTransactionManager.rollback(ts);

            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

    }

    public void userUpdate(String sidIdent, InputStream user) throws EAuthServerLogic {
        Map<String, String> attrsAll = getUserAttrs(user);

        String sid = null;
        String login = null;
        String pwd = null;
        Map<String, String> attrs = new HashMap<>();

        for (Map.Entry<String, String> pair : attrsAll.entrySet()) {
            String key = pair.getKey();
            String value = pair.getValue();

            if ("sid".equalsIgnoreCase(key)) {
                sid = value;
                continue;
            }
            if ("login".equalsIgnoreCase(key)) {
                login = value;
                continue;
            }
            if ("pwd".equalsIgnoreCase(key)) {
                pwd = value;
                continue;
            }

            attrs.put(key, value);
        }


        String oldLogin;
        try {
            oldLogin = jdbcTemplate.queryForObject("SELECT login FROM \"" + table + "\" WHERE sid=?",
                    String.class, sid);
        } catch (EmptyResultDataAccessException e) {
            oldLogin = null;
        }


        String sql = null;
        TransactionStatus ts = dataSourceTransactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            if (!(isNull(login) && isNull(pwd))) {
                String fields = "";
                if (nonNull(login)) {
                    fields = "login = ?";
                }
                if (nonNull(pwd)) {
                    fields = fields + (!fields.isEmpty() ? ", " : "") + "pwd = ?";
                }

                sql = "UPDATE \"" + table + "\" SET " + fields + " WHERE sid = ?";

                ArrayList<String> params = new ArrayList<>();
                if (nonNull(login)) {
                    params.add(login);
                }
                if (nonNull(pwd)) {
                    params.add(pwd);
                }
                params.add(sidIdent);

                jdbcTemplate.update(sql, params.toArray());
            }

            attrs.forEach((k, v) -> jdbcTemplate.update(
                    "INSERT INTO \"" + tableAttr + "\" (sid, fieldid, fieldvalue) VALUES (?, ?, ?)" + " ON CONFLICT (sid, fieldid) DO UPDATE SET fieldvalue = ? WHERE (\"" + tableAttr + "\".sid=?) AND (\"" + tableAttr + "\".fieldid=?)",
                    sidIdent, k, v, v, sidIdent, k));

            dataSourceTransactionManager.commit(ts);

            AuthManager.getTheManager().updateUserInfoByUserUpdate(oldLogin, login, pwd);
        } catch (Exception e) {
            dataSourceTransactionManager.rollback(ts);

            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

    }

    public void userDelete(String sid) throws EAuthServerLogic {
        String login;
        try {
            login = jdbcTemplate.queryForObject("SELECT login FROM \"" + table + "\" WHERE sid=?", String.class, sid);
        } catch (EmptyResultDataAccessException e) {
            login = null;
        }

        String sql = null;
        TransactionStatus ts = dataSourceTransactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            sql = "DELETE FROM \"" + tableAttr + "\" WHERE sid=?";
            jdbcTemplate.update(sql, sid);

            sql = "DELETE FROM \"" + table + "\" WHERE sid=?";
            jdbcTemplate.update(sql, sid);

            dataSourceTransactionManager.commit(ts);

            AuthManager.getTheManager().logoutByUserDelete(login);
        } catch (Exception e) {
            dataSourceTransactionManager.rollback(ts);

            if (nonNull(getLogger())) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

    }

    private static class Credentials {
        private String sid;
        private String login;
        private String pwd;

        public String getSid() {
            return sid;
        }

        public void setSid(String sid) {
            this.sid = sid;
        }

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
    }

    private static class CredentialsRowMapper implements RowMapper<Credentials> {
        @Override
        public Credentials mapRow(ResultSet rs, int rowNum) throws SQLException {
            Credentials credentials = new Credentials();
            credentials.setSid(rs.getString("sid"));
            credentials.setLogin(rs.getString("login"));
            credentials.setPwd(rs.getString("pwd"));
            return credentials;
        }
    }


    private static class Attrs {
        private String sid;
        private String fieldid;
        private String fieldvalue;

        public String getSid() {
            return sid;
        }

        public void setSid(String sid) {
            this.sid = sid;
        }

        public String getFieldid() {
            return fieldid;
        }

        public void setFieldid(String fieldid) {
            this.fieldid = fieldid;
        }

        public String getFieldvalue() {
            return fieldvalue;
        }

        public void setFieldvalue(String fieldvalue) {
            this.fieldvalue = fieldvalue;
        }
    }

    private static class AttrsRowMapper implements RowMapper<Attrs> {
        @Override
        public Attrs mapRow(ResultSet rs, int rowNum) throws SQLException {
            Attrs attrs = new Attrs();
            attrs.setSid(rs.getString("sid"));
            attrs.setFieldid(rs.getString("fieldid"));
            attrs.setFieldvalue(rs.getString("fieldvalue"));
            return attrs;
        }
    }


    private static class AttrsExt {
        private String sid;
        private String login;
        private String fieldid;
        private String fieldvalue;

        public String getSid() {
            return sid;
        }

        public void setSid(String sid) {
            this.sid = sid;
        }

        public String getLogin() {
            return login;
        }

        public void setLogin(String login) {
            this.login = login;
        }

        public String getFieldid() {
            return fieldid;
        }

        public void setFieldid(String fieldid) {
            this.fieldid = fieldid;
        }

        public String getFieldvalue() {
            return fieldvalue;
        }

        public void setFieldvalue(String fieldvalue) {
            this.fieldvalue = fieldvalue;
        }
    }

    private static class AttrsExtRowMapper implements RowMapper<AttrsExt> {
        @Override
        public AttrsExt mapRow(ResultSet rs, int rowNum) throws SQLException {
            AttrsExt attrs = new AttrsExt();
            attrs.setSid(rs.getString("sid"));
            attrs.setLogin(rs.getString("login"));
            attrs.setFieldid(rs.getString("fieldid"));
            attrs.setFieldvalue(rs.getString("fieldvalue"));
            return attrs;
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


}
