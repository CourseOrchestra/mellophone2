package ru.curs.mellophone.logic;

import org.slf4j.LoggerFactory;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.sql.DataSource;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static java.lang.Math.min;


/**
 * Конфигурация подключения к SQL-серверу.
 */
public final class SQLExtLoginProvider extends AbstractLoginProvider {

    private static final String USER = "Пользователь '";
    private static final String USER_LOGIN = "Логин пользователя '";
    private static final String ERROR_SQL_SERVER = "Ошибка при работе с базой '%s': %s. Запрос: '%s'";

    private static final String USER_IS_BLOCKED_PERMANENTLY = "User %s is blocked permanently.";

    private static final String PASSWORD_DIVIDER = "#";

    private static final String PBKDF2 = "pbkdf2";
    private static final String PBKDF2_PASSWORD_DIVIDER = "\\$";
    private static final String PBKDF2_ALG_DIVIDER = ":";

    private static ConcurrentHashMap<String, MessageDigest> mdPool = new ConcurrentHashMap<String, MessageDigest>(4);

    private final HashMap<String, String> searchReturningAttributes = new HashMap<String, String>();
    private String fieldLogin = "login";
    private String fieldPassword = "pwd";
    private String connectionUsername;
    private String connectionPassword;
    private String table;
    private String tableAttr;
    private String fieldBlocked = null;
    private String hashAlgorithm = "SHA-256";
    private String localSecuritySalt = "";
    private String procPostProcess = null;

    private DataSource dataSource = null;

    private static void checkForPossibleSQLInjection(String sql, String errMsg) throws EAuthServerLogic {
        if (sql.indexOf(" ") > -1) throw EAuthServerLogic.create(errMsg);
    }

    @Override
    void setupLogger(boolean isLogging) {
        if (isLogging) {
            setLogger(LoggerFactory.getLogger(SQLExtLoginProvider.class));
        }
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


    private synchronized Connection getConnection() throws SQLException {
        if (dataSource == null) {
            DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
            dataSourceBuilder.url(getConnectionUrl());
            dataSourceBuilder.username(connectionUsername);
            dataSourceBuilder.password(connectionPassword);
            dataSource = dataSourceBuilder.build();
        }

        return dataSource.getConnection();
    }


    @Override
    void connect(String sesid, String login, String password, String ip, ProviderContextHolder context, PrintWriter pw) throws EAuthServerLogic {

        if (getLogger() != null) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("login='" + login + "'");
        }

        checkForPossibleSQLInjection(login, USER_LOGIN + login + "' в '" + getConnectionUrl() + "' не успешен");

        boolean success = false;
        String message = "";
        String sql = "";
        BadLoginType blt = BadLoginType.BAD_CREDENTIALS;
        try {

            ((SQLLink) context).conn = getConnection();

            sql = String.format("SELECT sid, login, pwd FROM \"%s\" WHERE \"login\" = ?", table);

            PreparedStatement stat = ((SQLLink) context).conn.prepareStatement(sql);

            stat.setString(1, login);

            boolean hasResult = stat.execute();
            if (hasResult) {
                ResultSet rs = stat.getResultSet();
                if (rs.next()) {

                    if ((procPostProcess == null) && (fieldBlocked != null)) {
                        if (rs.getBoolean(fieldBlocked)) {
                            success = false;
                            message = String.format(USER_IS_BLOCKED_PERMANENTLY, login);
                            blt = BadLoginType.USER_BLOCKED_PERMANENTLY;
                        }
                    }

                    if (blt != BadLoginType.USER_BLOCKED_PERMANENTLY) {

                        String pwdComplex = rs.getString(fieldPassword);
                        success = (pwdComplex != null) && ((!AuthManager.getTheManager().isCheckPasswordHashOnly()) && pwdComplex.equals(password) || checkPasswordHash(pwdComplex, password));

                        StringWriter sw = new StringWriter();
                        writeReturningAttributes(((SQLLink) context).conn, sw, rs);
                        sw.flush();

                        rs.close();

                        if (procPostProcess != null) {

                            PostProcessResult ppr = callProcPostProcess(((SQLLink) context).conn, sesid, login, success, sw.toString(), ip, false, LockoutManager.getLockoutManager().getAttemptsCount(login) + 1, LockoutManager.getLockoutTime() * 60);
                            success = success && ppr.isSuccess();
                            message = ppr.getMessage();

                        } else {
                            if (success) {
                                message = USER_LOGIN + login + "' в '" + getConnectionUrl() + "' успешен!";
                            }
                        }


                        if (success && (pw != null)) {
                            //writeReturningAttributes(pw, rs);
                            pw.append(sw.toString());
                        }

                    }

                } else {

                    if (procPostProcess != null) {

                        PostProcessResult ppr = callProcPostProcess(((SQLLink) context).conn, sesid, login, false, null, ip, false, LockoutManager.getLockoutManager().getAttemptsCount(login) + 1, LockoutManager.getLockoutTime() * 60);

                        message = ppr.getMessage();

                    }

                }
            }
        } catch (Exception e) {
            if (getLogger() != null) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

        if (!success && message.isEmpty()) {
            message = USER_LOGIN + login + "' в '" + getConnectionUrl() + "' не успешен: " + BAD_CREDENTIALS;
        }

        if (getLogger() != null) {
            getLogger().info(message);
        }

        if (!success) {
            EAuthServerLogic eas = EAuthServerLogic.create(message);
            eas.setBadLoginType(blt);
            throw eas;
        }

    }

    private void writeReturningAttributes(Connection conn, Writer writer, ResultSet rs) throws XMLStreamException, FactoryConfigurationError, SQLException {

        String sid = rs.getString("sid");
        String login = rs.getString("login");

        rs.close();

        XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(writer);
        xw.writeStartDocument("utf-8", "1.0");
        xw.writeEmptyElement("user");

        writeXMLAttr(xw, "sid", sid);
        writeXMLAttr(xw, "login", login);

        String sql = String.format("SELECT * FROM \"%s\" WHERE \"sid\" = ?", tableAttr);
        PreparedStatement stat = conn.prepareStatement(sql);
        stat.setString(1, sid);
        boolean hasResult = stat.execute();
        if (hasResult) {
            ResultSet rsAttr = stat.getResultSet();
            while (rsAttr.next()) {
                writeXMLAttr(xw, rsAttr.getString("fieldid"), rsAttr.getString("fieldvalue"));
            }
        }

        xw.writeEndDocument();
        xw.flush();
    }

    public PostProcessResult callProcPostProcess(Connection conn, String sesid, String login, boolean isauth, String attributes, String ip, boolean islocked, int attemptsCount, long timeToUnlock) throws SQLException {

        if (conn == null) {
            conn = getConnection();
        }

        CallableStatement cs = conn.prepareCall(String.format("{? = call %s (?, ?, ?, ?, ?, ?, ?, ?, ?)}", procPostProcess));

        cs.registerOutParameter(1, Types.INTEGER);
        cs.setString(2, sesid);
        cs.setString(3, login);
        cs.setBoolean(4, isauth);
        cs.setString(5, attributes);
        cs.setString(6, ip);
        cs.setBoolean(7, islocked);
        cs.setInt(8, attemptsCount);
        cs.setLong(9, timeToUnlock);
        cs.registerOutParameter(10, Types.VARCHAR);

        cs.execute();

        return new PostProcessResult(cs.getInt(1) == 0, "Stored procedure message begin: " + cs.getString(10) + " Stored procedure message end.");

    }

    private boolean checkPasswordHash(String pwdComplex, String password) throws UnsupportedEncodingException, EAuthServerLogic {

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

        if (getLogger() != null) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("name='" + name + "'");
        }

        checkForPossibleSQLInjection(name, USER + name + "' не найден");

        String sql = "";
        try {
            ((SQLLink) context).conn = getConnection();

            sql = String.format("SELECT sid, login FROM \"%s\" WHERE \"login\" = ?", table);
            PreparedStatement stat = ((SQLLink) context).conn.prepareStatement(sql);
            stat.setString(1, name);

            boolean hasResult = stat.execute();
            if (hasResult) {
                ResultSet rs = stat.getResultSet();
                if (rs.next()) {
                    StringWriter sw = new StringWriter();
                    writeReturningAttributes(((SQLLink) context).conn, sw, rs);
                    sw.flush();

                    pw.append(sw.toString());

                    rs.close();

                    return;
                }
            }

            if (getLogger() != null) {
                getLogger().info(USER + name + "' не найден");
            }

        } catch (Exception e) {
            if (getLogger() != null) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }
    }

    @Override
    void changePwd(ProviderContextHolder context, String userName, String newpwd) throws EAuthServerLogic {

        if (getLogger() != null) {
            getLogger().info("Url='" + getConnectionUrl() + "'");
            getLogger().info("name='" + userName + "'");
        }

        checkForPossibleSQLInjection(userName, USER + userName + "' не найден");

        String sql = "";
        try {
            ((SQLLink) context).conn = getConnection();

            sql = String.format("UPDATE \"%s\" SET \"%s\" = ? WHERE \"%s\" = ?", table, fieldPassword, fieldLogin);

            PreparedStatement stat = ((SQLLink) context).conn.prepareStatement(sql);


            SecureRandom r = new SecureRandom();
            String salt = String.format("%016x", r.nextLong()) + String.format("%016x", r.nextLong());

            String password = getHashAlgorithm1(hashAlgorithm) + PASSWORD_DIVIDER + salt + PASSWORD_DIVIDER + getHash(newpwd + salt + localSecuritySalt, hashAlgorithm);


            stat.setString(1, password);
            stat.setString(2, userName);

            stat.execute();

        } catch (Exception e) {
            if (getLogger() != null) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        }

    }


    @Override
    void importUsers(ProviderContextHolder context, PrintWriter pw, boolean needStartDocument) throws EAuthServerLogic {
        if (getLogger() != null) {
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

            ((SQLLink) context).conn = getConnection();
            sql = String.format("SELECT a.sid, a.login, b.fieldid, b.fieldvalue FROM \"%s\" a LEFT OUTER JOIN \"%s\" b ON a.sid = b.sid ORDER BY a.sid", table, tableAttr);
            PreparedStatement stat = ((SQLLink) context).conn.prepareStatement(sql);

            boolean hasResult = stat.execute();
            if (hasResult) {
                ResultSet rs = stat.getResultSet();
                String sid = "";
                while (rs.next()) {
                    if (!sid.equals(rs.getString("sid"))) {
                        xw.writeEmptyElement("user");
                        writeXMLAttr(xw, "sid", rs.getString("sid"));
                        writeXMLAttr(xw, "login", rs.getString("login"));
                        sid = rs.getString("sid");
                    }
                    if (rs.getString("fieldid") != null) {
                        writeXMLAttr(xw, rs.getString("fieldid"), rs.getString("fieldvalue"));
                    }
                }
                rs.close();

                xw.writeEndDocument();
                xw.flush();
                if (getLogger() != null) {
                    getLogger().info("Импорт пользователей успешно завершен");
                }
            }
        } catch (Exception e) {
            if (getLogger() != null) {
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
     *
     * @throws UnsupportedEncodingException
     * @throws EAuthServerLogic
     */
    private String getHash(String input, String alg) throws UnsupportedEncodingException, EAuthServerLogic {

        MessageDigest md = mdPool.get(alg);
        if (md == null) {
            try {
                md = MessageDigest.getInstance(alg);
                if (mdPool.get(alg) == null) {
                    mdPool.put(alg, md);
                }
            } catch (NoSuchAlgorithmException e) {
                if (getLogger() != null) {
                    getLogger().error(e.getMessage());
                }
                throw EAuthServerLogic.create("Алгоритм хеширования " + alg + " не доступен");
            }
        }

        synchronized (md) {
            md.reset();
            md.update(input.getBytes("UTF-8"));
            return asHex(md.digest());
        }

    }

    private String getHashForPBKDF2(String password, String salt, int iterations) throws EAuthServerLogic {
        final int keyLength = 256;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] hashedBytes = key.getEncoded();
            //String res = "Hex.encodeHexString(hashedBytes)";
            HexFormat commaFormat = HexFormat.of();
            String res = commaFormat.formatHex(hashedBytes);
            return res;
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
            Map<String, String> out = new HashMap<String, String>();

            @Override
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
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
        Map<String, String> attrs = new HashMap<String, String>();

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

        if (sid == null) {
            throw EAuthServerLogic.create("Атрибут пользователя sid не задан");
        }


        SQLLink context = new SQLLink();
        String sql = null;
        try {
            context.conn = getConnection();
            context.conn.setAutoCommit(false);

            String fields = "sid" + (login != null ? ", login" : "") + (pwd != null ? ", pwd" : "");
            String values = "?" + (login != null ? ", ?" : "") + (pwd != null ? ", ?" : "");
            sql = "INSERT INTO \"" + table + "\" (" + fields + ") VALUES (" + values + ")";

            PreparedStatement stat = context.conn.prepareStatement(sql);

            int i = 1;
            stat.setString(i, sid);
            if (login != null) {
                i++;
                stat.setString(i, login);
            }
            if (pwd != null) {
                i++;
                stat.setString(i, pwd);
            }

            stat.execute();


            if (attrs.size() > 0) {
                sql = "INSERT INTO \"" + tableAttr + "\" (sid, fieldid, fieldvalue) VALUES (?, ?, ?)";
                stat = context.conn.prepareStatement(sql);
                for (Map.Entry<String, String> pair : attrs.entrySet()) {
                    stat.setString(1, sid);
                    stat.setString(2, pair.getKey());
                    stat.setString(3, pair.getValue());
                    stat.execute();
                }
            }

            context.conn.commit();
        } catch (Exception e) {
            try {
                context.conn.rollback();
            } catch (SQLException e2) {
            }

            if (getLogger() != null) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        } finally {
            context.closeContext();
        }

    }

    public void userUpdate(String sidIdent, InputStream user) throws EAuthServerLogic {
        Map<String, String> attrsAll = getUserAttrs(user);

        String sid = null;
        String login = null;
        String pwd = null;
        Map<String, String> attrs = new HashMap<String, String>();

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


        SQLLink context = new SQLLink();
        String sql = null;
        try {
            String oldLogin = null;

            context.conn = getConnection();
            sql = "SELECT login FROM \"" + table + "\" WHERE sid=?";
            PreparedStatement stat = context.conn.prepareStatement(sql);
            stat.setString(1, sid);
            boolean hasResult = stat.execute();
            if (hasResult) {
                ResultSet rs = stat.getResultSet();
                while (rs.next()) {
                    oldLogin = rs.getString("login");
                }
                rs.close();
            }

            context.conn.setAutoCommit(false);

            if (!((login == null) && (pwd == null))) {
                String fields = "";
                if (login != null) {
                    fields = "login = ?";
                }
                if (pwd != null) {
                    fields = fields + (!fields.isEmpty() ? ", " : "") + "pwd = ?";
                }

                sql = "UPDATE \"" + table + "\" SET " + fields + " WHERE sid = ?";

                stat = context.conn.prepareStatement(sql);

                int i = 0;
                if (login != null) {
                    i++;
                    stat.setString(i, login);
                }
                if (pwd != null) {
                    i++;
                    stat.setString(i, pwd);
                }
                i++;
                stat.setString(i, sidIdent);

                stat.execute();
            }

            if (attrs.size() > 0) {
                sql = "INSERT INTO \"" + tableAttr + "\" (sid, fieldid, fieldvalue) VALUES (?, ?, ?)" + " ON CONFLICT (sid, fieldid) DO UPDATE SET fieldvalue = ? WHERE (\"" + tableAttr + "\".sid=?) AND (\"" + tableAttr + "\".fieldid=?)";
                stat = context.conn.prepareStatement(sql);
                for (Map.Entry<String, String> pair : attrs.entrySet()) {
                    stat.setString(1, sidIdent);
                    stat.setString(2, pair.getKey());
                    stat.setString(3, pair.getValue());
                    stat.setString(4, pair.getValue());
                    stat.setString(5, sidIdent);
                    stat.setString(6, pair.getKey());
                    stat.execute();
                }
            }

            context.conn.commit();

            AuthManager.getTheManager().updateUserInfoByUserUpdate(oldLogin, login, pwd);
        } catch (Exception e) {
            try {
                context.conn.rollback();
            } catch (SQLException e2) {
            }

            if (getLogger() != null) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        } finally {
            context.closeContext();
        }

    }

    public void userDelete(String sid) throws EAuthServerLogic {
        SQLLink context = new SQLLink();
        String sql = null;
        try {
            String login = null;

            context.conn = getConnection();
            sql = "SELECT login FROM \"" + table + "\" WHERE sid=?";
            PreparedStatement stat = context.conn.prepareStatement(sql);
            stat.setString(1, sid);
            boolean hasResult = stat.execute();
            if (hasResult) {
                ResultSet rs = stat.getResultSet();
                while (rs.next()) {
                    login = rs.getString("login");
                }
                rs.close();
            }

            context.conn.setAutoCommit(false);

            sql = "DELETE FROM \"" + tableAttr + "\" WHERE sid=?";
            stat = context.conn.prepareStatement(sql);
            stat.setString(1, sid);
            stat.execute();

            sql = "DELETE FROM \"" + table + "\" WHERE sid=?";
            stat = context.conn.prepareStatement(sql);
            stat.setString(1, sid);
            stat.execute();

            context.conn.commit();

            AuthManager.getTheManager().logoutByUserDelete(login);
        } catch (Exception e) {
            try {
                context.conn.rollback();
            } catch (SQLException e2) {
            }

            if (getLogger() != null) {
                getLogger().error(String.format(ERROR_SQL_SERVER, getConnectionUrl(), e.getMessage(), sql));
            }
            throw EAuthServerLogic.create(e);
        } finally {
            context.closeContext();
        }

    }


    /**
     * Контекст соединения с базой данных.
     */
    private class SQLLink extends ProviderContextHolder {
        private Connection conn = null;

        @Override
        void closeContext() {
            try {
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

    }


}
