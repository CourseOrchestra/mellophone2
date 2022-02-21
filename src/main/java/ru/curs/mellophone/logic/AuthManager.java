package ru.curs.mellophone.logic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;


/**
 * Менеджер системы аутентификации.
 */
public final class AuthManager {

    /**
     * Указывает на то, что нужно опрашивать все провайдеры, игнорируя группу.
     */
    public static final String GROUP_PROVIDERS_ALL = "all";
    /**
     * Указывает на то, что нужно опрашивать провайдеры с незаданной(или пустой)
     * группой.
     */
    public static final String GROUP_PROVIDERS_NOT_DEFINE = "not_defined";
    /**
     * Директория с настройками.
     */
    public static final String DIR_CONFIG = "config/";
    private static final String ERROR_PARSING_CONFIG_XML = "Ошибка при разборе файла конфигурации config.xml: %s";
    private static final String SESID_NOT_AUTH = "Сессия приложения с идентификатором %s не аутентифицирована.";
    private static final String PROVIDER_ERROR = "При взаимодействии с логин-провайдером произошла следующая ошибка: %s";
    private static final String LOGIN_TO_PROVIDER_SUCCESSFUL_BUT_USER_NOT_FOUND_IN_BASE = "Логин " + "прошел успешно, но данный пользователь не найден в базе.";
    private static final String USER_IS_LOCKED_OUT_FOR_TOO_MANY_UNSUCCESSFUL_LOGIN_ATTEMPTS = "User %s is locked out for too many unsuccessful login attempts.";
    private static final String TIME_TO_UNLOCK = "Time to unlock: %s s.";
    /**
     * Период срабатывания таймера закрытия сессий по логауту, минуты.
     */
    private static final int TIMER_PERIOD = 60;
    private static final long MILLISECSINMINUTE = 60000;
    private static Logger LOGGER;
    private static AuthManager theMANAGER;
    private static ESIALoginProvider esiaLoginProvider = null;
    /**
     * Список зарегистрированных провайдеров.
     */
    private final LinkedList<AbstractLoginProvider> loginProviders = new LinkedList<>();
    /**
     * Залоченные (за повторное использование паролей) пользователи.
     */
    private final LockoutManager lockouts = LockoutManager.getLockoutManager();
    /**
     * Список сессий аутентификации.
     */
    private ConcurrentHashMap<String, AuthSession> authsessions;
    /**
     * Привязка сессий приложений к сессиям аутентификации.
     */
    private ConcurrentHashMap<String, String> appsessions;
    private ConcurrentHashMap<String, String> statesessions;
    /**
     * Параметры authsessions и appsessions.
     */
    private int authsessionsInitialCapacity = 16;
    private float authsessionsLoadFactor = (float) 0.75;
    private int authsessionsConcurrencyLevel = 16;
    private int appsessionsInitialCapacity = 16;
    private float appsessionsLoadFactor = (float) 0.75;
    private int appsessionsConcurrencyLevel = 16;
    private boolean checkPasswordHashOnly = false;
    /**
     * Количество потоков, параллельно опрашивающих логин-провайдеры.
     */
    private int threadCount = 4;
    private int sessionTimeout = 0;
    private Timer timerTimeout = null;
    private String settingsToken = null;
    private String getuserlistToken = null;
    private String configPath = null;
    private boolean showTimeToUnlockUser = false;
    private SQLLoginProvider procPostProcessProvider = null;
    private SQLExtLoginProvider procPostProcessExtProvider = null;

    /**
     * Возвращает единственный экземпляр (синглетон) менеджера системы
     * аутентификации.
     */
    public static AuthManager getTheManager() {
        if (isNull(theMANAGER)) {
            theMANAGER = new AuthManager();
        }
        return theMANAGER;
    }

    public LinkedList<AbstractLoginProvider> getLoginProviders() {
        return loginProviders;
    }

    public boolean isCheckPasswordHashOnly() {
        return checkPasswordHashOnly;
    }

    /**
     * Destroy приложения в рабочем режиме.
     */
    public void productionModeDestroy() {
        if (nonNull(timerTimeout)) {
            timerTimeout.cancel();
        }
    }

    /**
     * Инициализация приложения в рабочем режиме.
     */
    public void productionModeInitialize(String mellophoneConfigFile) {

        configPath = mellophoneConfigFile;

        try {
            File configFile = new File(configPath);
            if (!configFile.exists()) {
                throw EAuthServerLogic.create("Файл конфигурации " + configFile.getCanonicalPath() + " не существует.");
            }

            LOGGER = LoggerFactory.getLogger(AuthManager.class);

            ConfigParser p = new ConfigParser();
            try {
                SaxonTransformerFactory.newInstance().newTransformer()
                        .transform(new StreamSource(configFile), new SAXResult(p));
            } catch (Exception e) {
                throw EAuthServerLogic.create(
                        "Произошла ошибка при чтении файла конфигурации " + configFile.getCanonicalPath() + " " + e.getMessage());
            }

            if (loginProviders.stream().filter(lp -> "sqlserverext".equals(lp.getType())).toList()
                    .size() > 1) {
                throw EAuthServerLogic.create(
                        "Файл конфигурации " + configFile.getCanonicalPath() + " содержит более одного sqlserverext провайдера аутентификации");
            }

            commonInitialize();

        } catch (Exception e) {
            throw EAuthServerLogic.create(e);
        }

    }

    /**
     * Инициализация приложения для тестов.
     *
     * @throws EAuthServerLogic исключение
     */
    public void testModeInitialize() throws EAuthServerLogic {
        ConfigParser p = new ConfigParser();
        try {
            File configTestFile = new File("./src/test/resources/config_test.xml");
            InputStream is = new FileInputStream(configTestFile);

            SaxonTransformerFactory.newInstance().newTransformer().transform(new StreamSource(is), new SAXResult(p));
        } catch (Exception e) {
            throw EAuthServerLogic.create(String.format(ERROR_PARSING_CONFIG_XML, e.getMessage()));
        }

        commonInitialize();
    }

    private void commonInitialize() {
        loginProviders.forEach(AbstractLoginProvider::initialize);

        authsessions = new ConcurrentHashMap<>(authsessionsInitialCapacity, authsessionsLoadFactor,
                authsessionsConcurrencyLevel);
        appsessions = new ConcurrentHashMap<>(appsessionsInitialCapacity, appsessionsLoadFactor,
                appsessionsConcurrencyLevel);
        statesessions = new ConcurrentHashMap<>();

        if (sessionTimeout > 0) {
            timerTimeout = new Timer();
            long delay = MILLISECSINMINUTE * TIMER_PERIOD;
            timerTimeout.schedule(new TimerTask() {
                @Override
                public void run() {
                    AuthManager.getTheManager().logoutByTimer();
                }
            }, delay, delay);
        }
    }

    public void checkCredentials(final String groupProviders, final String login, final String password, final String ip, final PrintWriter pw) throws EAuthServerLogic {

        if (lockouts.isLocked(login)) {
            String s = getMessageUserIslockedOutForTooManyUnsuccessfulLoginAttempts(null, login, ip);

            LOGGER.error(s);

            throw EAuthServerLogic.create(s);
        }

        final StringBuffer errlog = new StringBuffer();
        final StringBuffer resumeMessage = new StringBuffer();
        final Vector<AbstractLoginProvider> result = new Vector<>(1);
        final Vector<AbstractLoginProvider> taskPool = new Vector<>(loginProviders.size());
        for (AbstractLoginProvider p : loginProviders)
            if ((GROUP_PROVIDERS_ALL.equalsIgnoreCase(groupProviders)) || (groupProviders.equals(
                    p.getGroupProviders())))
                taskPool.add(p);


        class ThreadsHandler {
            private int c = threadCount;

            synchronized void markThreadFinish() {
                c--;
                notify();
            }

            synchronized boolean isFinished() {
                return c <= 0;
            }
        }
        final ThreadsHandler h = new ThreadsHandler();

        class LoginThread extends Thread {
            private AbstractLoginProvider getNext() {
                synchronized (taskPool) {
                    return taskPool.size() == 0 ? null : taskPool.remove(taskPool.size() - 1);
                }
            }

            @Override
            public void run() {
                AbstractLoginProvider curProvider = getNext();
                while (nonNull(curProvider)) {
                    try {
                        ProviderContextHolder ch = curProvider.newContextHolder();
                        try {

                            curProvider.connect(null, login, password, ip, ch, pw);

                            if ((!"SQLLoginProvider".equalsIgnoreCase(curProvider.getClass()
                                    .getSimpleName())) && (!"SQLExtLoginProvider".equalsIgnoreCase(
                                    curProvider.getClass().getSimpleName())) && (!"IASBPLoginProvider".equalsIgnoreCase(
                                    curProvider.getClass().getSimpleName()))) {
                                curProvider.getUserInfoByName(ch, login, pw);
                                if ("".equals(pw.toString().trim())) {
                                    throw EAuthServerLogic.create(
                                            LOGIN_TO_PROVIDER_SUCCESSFUL_BUT_USER_NOT_FOUND_IN_BASE);
                                }
                            }


                        } finally {
                            ch.closeContext();
                        }
                        // Если коннект прошёл без ошибок, то значит, мы нашли
                        // коннектор и выходим из цикла.
                        result.add(curProvider);
                        break;
                    } catch (EAuthServerLogic e) {
                        errlog.append(curProvider.getConnectionUrl()).append(": ").append(e.getMessage()).append("\n");

                        if (e.getBadLoginType() == BadLoginType.BAD_PROC_CHECK_USER) {
                            resumeMessage.delete(0, resumeMessage.length());
                            resumeMessage.append(e.getMessage());
                        } else {
                            if (resumeMessage.length() == 0) {
                                resumeMessage.append("Неправильная пара логин/пароль");
                            }
                        }

                    }
                    curProvider = getNext();
                }
                h.markThreadFinish();
            }
        }

        Thread[] procs = new LoginThread[threadCount];
        for (int i = 0; i < procs.length; i++) {
            procs[i] = new LoginThread();
            procs[i].start();
        }
        synchronized (h) {
            while (result.size() == 0 && !h.isFinished()) {
                try {
                    h.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        if (result.size() == 0) {
            if (errlog.toString().trim().isEmpty()) {
                errlog.append("Неправильная пара логин/пароль");
            }
            lockouts.loginFail(login);
            throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, errlog + "\nРезюме: " + resumeMessage));
        }


        lockouts.success(login);

    }


    public void getProviderList(final String groupProviders, final String login, final String password, final String ip, final PrintWriter pw) throws EAuthServerLogic {

        if (lockouts.isLocked(login)) {
            String s = getMessageUserIslockedOutForTooManyUnsuccessfulLoginAttempts(null, login, ip);

            LOGGER.error(s);

            throw EAuthServerLogic.create(s);
        }

        final StringBuffer errlog = new StringBuffer();
        final StringBuffer resumeMessage = new StringBuffer();
        final Vector<AbstractLoginProvider> result = new Vector<>(1);
        final Vector<AbstractLoginProvider> taskPool = new Vector<>(loginProviders.size());
        for (AbstractLoginProvider p : loginProviders)
            if ((GROUP_PROVIDERS_ALL.equalsIgnoreCase(groupProviders)) || (groupProviders.equals(
                    p.getGroupProviders())))
                taskPool.add(p);

        class ThreadsHandler {
            private int c = threadCount;

            synchronized void markThreadFinish() {
                c--;
                notify();
            }

            synchronized boolean isFinished() {
                return c <= 0;
            }
        }
        final ThreadsHandler h = new ThreadsHandler();

        class LoginThread extends Thread {
            private AbstractLoginProvider getNext() {
                synchronized (taskPool) {
                    return taskPool.size() == 0 ? null : taskPool.remove(taskPool.size() - 1);
                }

            }

            @Override
            public void run() {
                AbstractLoginProvider curProvider = getNext();
                while (nonNull(curProvider)) {
                    try {
                        ProviderContextHolder ch = curProvider.newContextHolder();
                        try {

                            curProvider.connect(null, login, password, ip, ch, null);

                            try {
                                XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
                                xw.writeStartDocument("utf-8", "1.0");
                                xw.writeStartElement("providers");
                                for (AbstractLoginProvider alp : loginProviders) {
                                    if ((GROUP_PROVIDERS_ALL.equalsIgnoreCase(
                                            groupProviders)) || (groupProviders.equals(alp.getGroupProviders()))) {
                                        xw.writeEmptyElement("provider");
                                        xw.writeAttribute("id", alp.getId());
                                        xw.writeAttribute("type", alp.getType());
                                        xw.writeAttribute("url", alp.getConnectionUrl());
                                        xw.writeAttribute("group_providers", alp.getGroupProviders());
                                    }
                                }
                                xw.writeEndDocument();
                                xw.flush();

                            } catch (XMLStreamException e) {
                                throw EAuthServerLogic.create(e);
                            }

                        } finally {
                            ch.closeContext();
                        }
                        // Если коннект прошёл без ошибок, то значит, мы нашли
                        // коннектор и выходим из цикла.
                        result.add(curProvider);
                        break;
                    } catch (EAuthServerLogic e) {
                        errlog.append(curProvider.getConnectionUrl()).append(": ").append(e.getMessage()).append("\n");

                        if (e.getBadLoginType() == BadLoginType.BAD_PROC_CHECK_USER) {
                            resumeMessage.delete(0, resumeMessage.length());
                            resumeMessage.append(e.getMessage());
                        } else {
                            if (resumeMessage.length() == 0) {
                                resumeMessage.append("Неправильная пара логин/пароль");
                            }
                        }

                    }
                    curProvider = getNext();
                }
                h.markThreadFinish();
            }
        }

        Thread[] procs = new LoginThread[threadCount];
        for (int i = 0; i < procs.length; i++) {
            procs[i] = new LoginThread();
            procs[i].start();
        }
        synchronized (h) {
            while (result.size() == 0 && !h.isFinished()) {
                try {
                    h.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        if (result.size() == 0) {
            if (errlog.toString().trim().isEmpty()) {
                errlog.append("Неправильная пара логин/пароль");
            }
            lockouts.loginFail(login);
            throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, errlog + "\nРезюме: " + resumeMessage));
        }


        lockouts.success(login);

    }


    public void getUserList(final String providerId, final String groupProviders, String token, final PrintWriter pw) throws EAuthServerLogic {

        if (isNull(getuserlistToken) || (!getuserlistToken.equals(token))) {
            throw EAuthServerLogic.create("Permission denied.");
        }

        if (nonNull(providerId)) {

            AbstractLoginProvider curProvider = null;

            for (AbstractLoginProvider p : loginProviders) {
                if (providerId.equals(p.getId())) {
                    curProvider = p;
                    break;
                }
            }

            if (isNull(curProvider)) {
                String s = String.format("/getuserlist (pid = %s). Провайдер не найден.", providerId);
                LOGGER.error(s);
                throw EAuthServerLogic.create(s);
            }


            try {
                ProviderContextHolder ch = curProvider.newContextHolder();
                try {
                    curProvider.importUsers(ch, pw, true);
                } finally {
                    ch.closeContext();
                }
            } catch (EAuthServerLogic e) {
                throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, e.getMessage()));
            }

        } else {

            boolean res = false;

            final StringBuilder errlog = new StringBuilder();
            errlog.append("/getuserlist.\n");

            for (AbstractLoginProvider curProvider : loginProviders) {
                if ((GROUP_PROVIDERS_ALL.equalsIgnoreCase(groupProviders)) || (Objects.equals(groupProviders,
                        curProvider.getGroupProviders()))) {

                    try {
                        ProviderContextHolder ch = curProvider.newContextHolder();
                        try {
                            curProvider.importUsers(ch, pw, !res);
                            res = true;
                        } finally {
                            ch.closeContext();
                        }
                    } catch (EAuthServerLogic e) {
                        String s = String.format(PROVIDER_ERROR, e.getMessage());
                        errlog.append(curProvider.getConnectionUrl()).append(": ").append(s).append("\n");
                    }

                }
            }

            if (!res) {
                throw EAuthServerLogic.create(errlog.toString());
            }

        }

    }

    private String getMessageUserIslockedOutForTooManyUnsuccessfulLoginAttempts(final String sesid, final String login, final String ip) {
        if (isNull(procPostProcessProvider) && isNull(procPostProcessExtProvider)) {
            String s = String.format(USER_IS_LOCKED_OUT_FOR_TOO_MANY_UNSUCCESSFUL_LOGIN_ATTEMPTS, login);
            if (showTimeToUnlockUser) {
                s = s + " " + String.format(TIME_TO_UNLOCK, lockouts.getTimeToUnlock(login));
            }
            return s;
        } else {
            if (nonNull(procPostProcessExtProvider)) {
                PostProcessResult ppr;
                try {
                    ppr = procPostProcessExtProvider.callProcPostProcess(sesid, login, false, null, ip, true,
                            LockoutManager.getLockoutManager().getAttemptsCount(login),
                            LockoutManager.getLockoutManager().getTimeToUnlock(login));
                } catch (Exception e) {
                    return e.getMessage();
                }
                return ppr.getMessage();
            }

            PostProcessResult ppr;
            try {
                ppr = procPostProcessProvider.callProcPostProcess(sesid, login, false, null, ip, true,
                        LockoutManager.getLockoutManager().getAttemptsCount(login),
                        LockoutManager.getLockoutManager().getTimeToUnlock(login));
            } catch (Exception e) {
                return e.getMessage();
            }
            return ppr.getMessage();
        }
    }

    /**
     * 1.Разаутентифицирует сессию с идентификатором приложения sesid и все
     * другие сессии приложений, соотносящиеся с той же сессией аутентификации.
     * 2.В случае, если пара «логин-пароль» верна, генерирует внутри себя
     * идентификатор сессии аутентификации и аутентифицирует сессию приложения
     * sesid
     *
     * @param sesid          Идентификатор сессии приложения для разаутентификации
     * @param groupProviders Идентификатор группы логинов
     * @param login          Логин
     * @param password       Пароль
     * @param ip             IP пользователя
     * @throws EAuthServerLogic В случае если пара «логин-пароль» не верна или при
     *                          взаимодействии с LDAP произошла другая ошибка
     */
    public String login(final String sesid, final String groupProviders, final String login, final String password, final String ip) throws EAuthServerLogic {

        logout(sesid);

        if (lockouts.isLocked(login)) {
            String s = getMessageUserIslockedOutForTooManyUnsuccessfulLoginAttempts(sesid, login, ip);

            LOGGER.error(s);

            throw EAuthServerLogic.create(s);
        }

        final ArrayList<String> userInfo = new ArrayList<>();
        final StringBuffer errlog = new StringBuffer();
        final StringBuffer resumeMessage = new StringBuffer();
        final Vector<AbstractLoginProvider> result = new Vector<>(1);
        final Vector<AbstractLoginProvider> taskPool = new Vector<>(loginProviders.size());
        for (AbstractLoginProvider p : loginProviders)
            if ((GROUP_PROVIDERS_ALL.equalsIgnoreCase(groupProviders)) || (groupProviders.equals(
                    p.getGroupProviders())))
                taskPool.add(p);

        class ThreadsHandler {
            private int c = threadCount;

            synchronized void markThreadFinish() {
                c--;
                notify();
            }

            synchronized boolean isFinished() {
                return c <= 0;
            }
        }
        final ThreadsHandler h = new ThreadsHandler();

        class LoginThread extends Thread {
            private AbstractLoginProvider getNext() {
                synchronized (taskPool) {
                    return taskPool.size() == 0 ? null : taskPool.remove(taskPool.size() - 1);
                }

            }

            @Override
            public void run() {
                AbstractLoginProvider curProvider = getNext();
                while (nonNull(curProvider)) {
                    try {
                        ProviderContextHolder ch = curProvider.newContextHolder();
                        try {

                            StringWriter sw = new StringWriter();
                            PrintWriter pw = new PrintWriter(sw);

                            curProvider.connect(sesid, login, password, ip, ch, pw);

                            if ((!"SQLLoginProvider".equalsIgnoreCase(curProvider.getClass()
                                    .getSimpleName())) && (!"SQLExtLoginProvider".equalsIgnoreCase(
                                    curProvider.getClass().getSimpleName())) && (!"IASBPLoginProvider".equalsIgnoreCase(
                                    curProvider.getClass().getSimpleName()))) {
                                curProvider.getUserInfoByName(ch, login, pw);
                                if ("".equals(sw.toString().trim())) {
                                    throw EAuthServerLogic.create(
                                            LOGIN_TO_PROVIDER_SUCCESSFUL_BUT_USER_NOT_FOUND_IN_BASE);
                                }
                            }

                            userInfo.add(sw.toString().trim());

                            if ("IASBPLoginProvider".equalsIgnoreCase(curProvider.getClass().getSimpleName())) {
                                userInfo.add(((IASBPLoginProvider) curProvider).getDjangoauthid());
                            }

                        } finally {
                            ch.closeContext();
                        }
                        // Если коннект прошёл без ошибок, то значит, мы нашли
                        // коннектор и выходим из цикла.
                        result.add(curProvider);
                        break;
                    } catch (EAuthServerLogic e) {
                        errlog.append(curProvider.getConnectionUrl()).append(": ").append(e.getMessage()).append("\n");

                        if (e.getBadLoginType() == BadLoginType.BAD_PROC_CHECK_USER) {
                            resumeMessage.delete(0, resumeMessage.length());
                            resumeMessage.append(e.getMessage());
                        } else {
                            if (resumeMessage.length() == 0) {
                                resumeMessage.append("Неправильная пара логин/пароль");
                            }
                        }

                    }
                    curProvider = getNext();
                }
                h.markThreadFinish();
            }
        }

        Thread[] procs = new LoginThread[threadCount];
        for (int i = 0; i < procs.length; i++) {
            procs[i] = new LoginThread();
            procs[i].start();
        }
        synchronized (h) {
            while (result.size() == 0 && !h.isFinished()) {
                try {
                    h.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        if (result.size() == 0) {
            if (errlog.toString().trim().isEmpty()) {
                errlog.append("Неправильная пара логин/пароль.");
            }
            lockouts.loginFail(login);

            if (isNull(procPostProcessProvider) && isNull(procPostProcessExtProvider) && lockouts.isLocked(login)) {
                String s = getMessageUserIslockedOutForTooManyUnsuccessfulLoginAttempts(sesid, login, ip);
                LOGGER.error(s);
                resumeMessage.append(". ").append(s);
            }

            throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, errlog + "\nРезюме: " + resumeMessage));
        }

        SecureRandom r = new SecureRandom();
        String authid = String.format("%016x", r.nextLong()) + String.format("%016x", r.nextLong());

        String djangoauthid = null;
        if (userInfo.size() > 1) {
            djangoauthid = userInfo.get(1);
        }

        authsessions.put(authid,
                new AuthSession(login, password, result.get(0), authid, userInfo.get(0), ip, djangoauthid));
        appsessions.put(sesid, authid);

        lockouts.success(login);
        return authid;

    }

    /**
     * Разаутентифицирует сессию с идентификатором приложения sesid и все другие
     * сессии приложений, соотносящиеся с той же сессией аутентификации.
     *
     * @param sesid Идентификатор сессии.
     */
    public void logout(String sesid) {
        String authid = appsessions.get(sesid);
        if (isNull(authid)) {
            return;
        }

        AuthSession as = authsessions.get(authid);
        if (!(sesid.contains("django")) && nonNull(as.config) && "IASBPLoginProvider".equalsIgnoreCase(
                as.config.getClass().getSimpleName())) {
            ((IASBPLoginProvider) as.config).disconnect(as.name, as.djangoauthid);
        }

        ArrayList<String> apps = new ArrayList<>();
        for (String app : appsessions.keySet()) {
            if (authid.equals(appsessions.get(app))) {
                apps.add(app);
            }
        }
        for (String app : apps) {
            appsessions.remove(app);
            statesessions.remove(app);
        }

        authsessions.remove(authid);
    }

    /**
     * Разаутентифицирует сессии по таймауту.
     */
    public void logoutByTimer() {

        ArrayList<String> auths = new ArrayList<>();
        for (AuthSession as : authsessions.values()) {
            if (as.lastAuthenticated + MILLISECSINMINUTE * sessionTimeout < System.currentTimeMillis()) {

                if (nonNull(as.config) && "IASBPLoginProvider".equalsIgnoreCase(
                        as.config.getClass().getSimpleName())) {
                    ((IASBPLoginProvider) as.config).disconnect(as.name, as.djangoauthid);
                }

                auths.add(as.authid);
            }
        }

        if (auths.size() > 0) {
            ArrayList<String> apps = new ArrayList<>();
            for (String app : appsessions.keySet()) {
                String authid = appsessions.get(app);
                for (String auth : auths) {
                    if (authid.equals(auth)) {
                        apps.add(app);
                        break;
                    }
                }
            }

            for (String auth : auths) {
                authsessions.remove(auth);
            }

            for (String app : apps) {
                appsessions.remove(app);
                statesessions.remove(app);
            }
        }

    }

    /**
     * Фиксирует смену сессии приложения.
     *
     * @param oldId Старый идентификатор сессии приложения.
     * @param newId Новый идентификатор сессии приложения.
     * @throws EAuthServerLogic Если сессия была не идентифицирована.
     */
    public void changeAppSessionId(String oldId, String newId) throws EAuthServerLogic {
        String authid = appsessions.get(oldId);
        if (nonNull(authid)) {
            String state = statesessions.get(oldId);
            statesessions.remove(oldId);
            statesessions.put(newId, state);

            appsessions.remove(oldId);
            appsessions.put(newId, authid);
        } else {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, oldId));
        }
    }

    public String isAuthenticated(String sesid, String ip) throws EAuthServerLogic {

        String authid = appsessions.get(sesid);
        if (isNull(authid)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid + "__1"));
        }

        AuthSession as = authsessions.get(authid);
        if (isNull(as)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid + "__2"));
        }

        if (nonNull(ip) && nonNull(as.getIp())) {
            if (!ip.equals(as.getIp())) {
                throw EAuthServerLogic.create("Изменился ip пользователя");
            }
        }

        if (sessionTimeout > 0) {
            as.lastAuthenticated = System.currentTimeMillis();
        }

        if (as.getUserInfo().trim().isEmpty() && nonNull(as.config)
                && (!"IASBPLoginProvider".equalsIgnoreCase(as.config.getClass().getSimpleName()))) {
            try {
                ProviderContextHolder context = as.config.newContextHolder();
                try {
                    if ((!"HTTPLoginProvider".equalsIgnoreCase(as.config.getClass().getSimpleName()))
                            && (!"SQLLoginProvider".equalsIgnoreCase(as.config.getClass().getSimpleName()))
                            && (!"SQLExtLoginProvider".equalsIgnoreCase(as.config.getClass().getSimpleName()))) {
                        as.config.connect(sesid, as.getName(), as.getPwd(), null, context, null);
                    }
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    PrintWriter pw = new PrintWriter(os);
                    as.config.getUserInfoByName(context, as.getName(), pw);
                    pw.flush();
                    as.setUserInfo(os.toString());
                } finally {
                    context.closeContext();
                }
            } catch (Exception e) {
                throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, e.getMessage()));
            }
        }

        return as.getUserInfo();

    }

    /**
     * Возвращает информацию о пользователе, если пользователь с таким именем
     * существует в директории, "" -- если пользователь с таким имененм не
     * существует, выбрасывает EAuthServerLogic -- если сессия с идентификатором
     * sesid не аутентифицирована или произошла ошибка при взаимодействии с
     * LDAP.
     *
     * @param sesid Идентификатор сессии
     * @param name  Имя пользователя
     * @param pw    PrintWriter, в который выводится информация о пользователе в
     *              формате XML
     * @throws EAuthServerLogic Если сессия с идентификатором sesid не аутентифицирована или
     *                          произошла ошибка при взаимодействии с LDAP
     */
    public void checkName(String sesid, String name, PrintWriter pw) throws EAuthServerLogic {
        String authid = appsessions.get(sesid);
        if (isNull(authid)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid));
        }

        AuthSession as = authsessions.get(authid);
        if (isNull(as)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid));
        }

        // as.restartTimer();

        try {
            ProviderContextHolder context = as.config.newContextHolder();
            try {
                if ((!"HTTPLoginProvider".equalsIgnoreCase(
                        as.config.getClass().getSimpleName())) && (!"SQLLoginProvider".equalsIgnoreCase(
                        as.config.getClass().getSimpleName())) && (!"SQLExtLoginProvider".equalsIgnoreCase(
                        as.config.getClass().getSimpleName()))) {
                    as.config.connect(sesid, as.getName(), as.getPwd(), null, context, null);
                }
                as.config.getUserInfoByName(context, name, pw);
            } finally {
                context.closeContext();
            }
        } catch (Exception e) {
            throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, e.getMessage()));
        }
    }

    /**
     * Выполняет попытку смены пароля текущего пользователя. Возвращает имя
     * аутентифицированного пользователя, если сессия с идентификатором сессии
     * приложения sesid аутентифицирована, старый пароль введён верно и новый
     * пароль соответствует политикам безопасности, выбрасывает EAuthServerLogic
     * -- если сессия с идентификатором sesid не аутентифицирована и/или старый
     * пароль введён неверно и/или новый пароль не соответсвует политикам
     * безопасности.
     *
     * @param sesid  Идентификатор сессии
     * @param oldpwd Старый пароль
     * @param newpwd Новый пароль
     * @return Имя аутентифицированного пользователя
     * @throws EAuthServerLogic Если сессия с идентификатором sesid не аутентифицирована
     *                          и/или старый пароль введён неверно и/или новый пароль не
     *                          соответсвует политикам безопасности
     */
    public String changeOwnPwd(String sesid, String oldpwd, String newpwd) throws EAuthServerLogic {
        String name;

        String authid = appsessions.get(sesid);
        if (isNull(authid)) throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid));

        AuthSession as = authsessions.get(authid);
        if (isNull(as)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid));
        }

        try {
            ProviderContextHolder context = as.config.newContextHolder();
            try {
                as.config.connect(sesid, as.getName(), oldpwd, null, context, null);
                as.config.changePwd(context, as.getName(), newpwd);
            } finally {
                context.closeContext();
            }

            as.setPwd(newpwd);

            name = as.getName();
        } catch (Exception e) {
            throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, e.getMessage()));
        }

        return name;
    }

    /**
     * Выполняет попытку смены пароля произвольного пользователя. Возвращает имя
     * аутентифицированного пользователя (под которым производилась смена
     * пароля), если сессия с идентификатором сессии приложения sesid
     * аутентифицирована и пароль изменен успешно, выбрасывает EAuthServerLogic
     * -- если сессия с идентификатором sesid не аутентифицирована и/или попытка
     * изменения пароля не успешна.
     *
     * @param sesid    Идентификатор сессии
     * @param userName Пользователь, чей пароль меняем
     * @param newpwd   Новый пароль
     * @return Имя аутентифицированного пользователя (под которым производилась
     * смена пароля)
     * @throws EAuthServerLogic Если сессия с идентификатором sesid не аутентифицирована
     *                          и/или попытка изменения пароля не успешна
     */
    public String changeUserPwd(String sesid, String userName, String newpwd) throws EAuthServerLogic {
        String name;

        String authid = appsessions.get(sesid);
        if (isNull(authid)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid));
        }

        AuthSession as = authsessions.get(authid);
        if (isNull(as)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid));
        }

        try {
            ProviderContextHolder context = as.config.newContextHolder();


            try {
                as.config.connect(sesid, as.getName(), as.getPwd(), null, context, null);
                as.config.changePwd(context, userName, newpwd);
            } finally {
                context.closeContext();
            }

            for (String id : authsessions.keySet()) {
                if (userName.equals(authsessions.get(id).getName())) {
                    authsessions.get(id).setPwd(newpwd);
                    break;
                }
            }


            name = as.getName();
        } catch (Exception e) {
            throw EAuthServerLogic.create(String.format(PROVIDER_ERROR, e.getMessage()));
        }

        return name;
    }

    /**
     * Если authsesid содержит идентификатор активной сессии аутентификации, то
     * возвращает "AUTH_OK". В противном случае, если sesid аутентифицировано,
     * то возвращает идентификатор сессии аутентификации, а если нет -- null.
     *
     * @param sesid     Идентификатор сессии приложения
     * @param authsesid Идентификатор сессии аутентификации
     * @return authsesid
     */
    public String authenticationGif(String sesid, String authsesid) {
        if (nonNull(authsesid)) {
            if (nonNull(authsessions.get(authsesid))) {
                appsessions.putIfAbsent(sesid, authsesid);
                return "AUTH_OK";
            }
        }
        return appsessions.get(sesid);
    }

    /**
     * Возвращает список групп провайдеров.
     *
     * @param pw PrintWriter со списком групп провайдеров.
     */
    public void importGroupsProviders(PrintWriter pw) {
        List<String> lst = new ArrayList<>();

        for (AbstractLoginProvider alp : loginProviders) {

            String groupProviders = alp.getGroupProviders();

            if (isNull(groupProviders) || (groupProviders.isEmpty())) {
                groupProviders = GROUP_PROVIDERS_NOT_DEFINE;
            }

            if (!lst.contains(groupProviders)) {
                lst.add(groupProviders);
            }

        }

        for (int i = 0; i < lst.size(); i++) {
            if (i == lst.size() - 1) {
                pw.append(lst.get(i));
            } else {
                pw.append(lst.get(i)).append(" ");
            }
        }
    }


    public void userCreate(String token, InputStream user) throws EAuthServerLogic {
        if (isNull(getuserlistToken) || (!getuserlistToken.equals(token))) {
            throw EAuthServerLogic.create("Permission denied.");
        }

        List<?> list = loginProviders.stream().filter(lp -> "sqlserverext".equals(lp.getType())).toList();

        if (list.size() == 0) {
            throw EAuthServerLogic.create(
                    "Файл конфигурации config.xml не содержит sqlserverext провайдера аутентификации");
        }

        SQLExtLoginProvider p = (SQLExtLoginProvider) list.get(0);
        p.userCreate(user);
    }

    public void userUpdate(String token, String sid, InputStream user) throws EAuthServerLogic {
        if (isNull(getuserlistToken) || (!getuserlistToken.equals(token))) {
            throw EAuthServerLogic.create("Permission denied.");
        }

        List<?> list = loginProviders.stream().filter(lp -> "sqlserverext".equals(lp.getType())).toList();

        if (list.size() == 0) {
            throw EAuthServerLogic.create(
                    "Файл конфигурации config.xml не содержит sqlserverext провайдера аутентификации");
        }

        SQLExtLoginProvider p = (SQLExtLoginProvider) list.get(0);
        p.userUpdate(sid, user);
    }

    public void userDelete(String token, String sid) throws EAuthServerLogic {
        if (isNull(getuserlistToken) || (!getuserlistToken.equals(token))) {
            throw EAuthServerLogic.create("Permission denied.");
        }

        List<?> list = loginProviders.stream().filter(lp -> "sqlserverext".equals(lp.getType())).toList();

        if (list.size() == 0) {
            throw EAuthServerLogic.create(
                    "Файл конфигурации config.xml не содержит sqlserverext провайдера аутентификации");
        }

        SQLExtLoginProvider p = (SQLExtLoginProvider) list.get(0);
        p.userDelete(sid);
    }

    public void updateUserInfoByUserUpdate(String oldLogin, String newLogin, String newPwd) {
        if (isNull(oldLogin)) {
            return;
        }

        List<AuthSession> authUpdate = authsessions.values().stream()
                .filter(authSession -> oldLogin.equals(authSession.getName())).toList();

        authUpdate.forEach(as -> {
            as.setName(newLogin);
            as.setPwd(newPwd);
            as.setUserInfo("");
        });
    }

    public void logoutByUserDelete(String login) {
        if (isNull(login)) {
            return;
        }

        List<String> authDel = authsessions.entrySet().stream().filter(e -> login.equals(e.getValue().getName()))
                .map(Map.Entry::getKey).toList();

        List<String> appDel = appsessions.entrySet().stream().filter(e -> authDel.contains(e.getValue()))
                .map(Map.Entry::getKey).toList();

        appsessions.keySet().removeAll(appDel);
        statesessions.keySet().removeAll(appDel);
        authsessions.keySet().removeAll(authDel);
    }


    /**
     * Устанавливает взаимосвязь сессии приложения джанго, сессии аутентификации
     * джанго и сессии аутентификации мелофона.
     *
     * @param djangosesid  Идентификатор сессии приложения джанго
     * @param djangoauthid Идентификатор сессии аутентификации джанго
     * @param login        Логин пользователя
     * @param name         Название пользователя
     * @param sid          SID пользователя
     * @return authsesid
     * @throws EAuthServerLogic В случае ошибки
     */
    public String setDjangoAuthId(final String djangosesid, final String djangoauthid, final String login, final String name, final String sid) throws EAuthServerLogic {

        logout(djangosesid);

        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        try {
            XMLStreamWriter xw = XMLOutputFactory.newInstance().createXMLStreamWriter(pw);
            xw.writeStartDocument("utf-8", "1.0");
            xw.writeEmptyElement("user");
            xw.writeAttribute("login", login);
            xw.writeAttribute("name", name);
            xw.writeAttribute("SID", sid);
            xw.writeEndDocument();
            xw.flush();
        } catch (XMLStreamException e) {
            throw EAuthServerLogic.create(e.getMessage());
        }

        SecureRandom r = new SecureRandom();
        String authid = String.format("%016x", r.nextLong()) + String.format("%016x", r.nextLong());

        AbstractLoginProvider iasbp = null;
        for (AbstractLoginProvider p : loginProviders) {
            if ("IASBPLoginProvider".equalsIgnoreCase(p.getClass().getSimpleName())) {
                iasbp = p;
                break;
            }
        }

        authsessions.put(authid, new AuthSession(login, null, iasbp, authid, sw.toString().trim(), null, djangoauthid));
        appsessions.put(djangosesid, authid);

        if (nonNull(iasbp) && nonNull(iasbp.getLogger())) {
            iasbp.getLogger().info("Логин пользователя из ИАС БП '" + login + "' посредством setDjangoAuthId успешен!");
        }

        return authid;

    }

    /**
     * Получает djangoauthid по переданному djangosesid.
     *
     * @param djangosesid    Идентификатор сессии приложения джанго
     * @param authsesid      Идентификатор сессии аутентификации мелофона из куки
     * @param djangoCallback Функция обратного вызова из джанго
     * @param pw             PrintWriter, в который выводится информация о пользователе в
     *                       формате JSON
     * @throws EAuthServerLogic Если сессия с идентификатором djangosesid не
     *                          аутентифицирована
     */
    public void getDjangoAuthId(final String djangosesid, final String authsesid, final String djangoCallback, PrintWriter pw) throws EAuthServerLogic {

        AuthSession as;

        if (isNull(authsesid)) {
            String authid = appsessions.get(djangosesid);
            if (isNull(authid)) {
                throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH,
                        djangosesid) + " Подробности: authsesid == null и не найден djangosesid.");
            }

            as = authsessions.get(authid);
            if (isNull(as)) {
                throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH,
                        djangosesid) + " Подробности: authsesid == null и не найден authid.");
            }
        } else {
            as = authsessions.get(authsesid);
            if (isNull(as)) {
                throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH,
                        djangosesid) + " Подробности: authsesid != null, но не найден AuthSession.");
            }

            appsessions.putIfAbsent(djangosesid, authsesid);

        }

        pw.append(djangoCallback).append("({\"django_auth_id\": \"").append(as.djangoauthid).append("\"});");

    }


    /**
     * Логинит ESIA пользователя
     *
     * @param sesid    Идентификатор сессии.
     * @param login    Логин пользователя
     * @param userInfo Информация о пользователе
     * @throws EAuthServerLogic Если возникает ошибка
     */
    public void loginESIAUser(String sesid, String login, String userInfo) throws EAuthServerLogic {

        if (isNull(esiaLoginProvider)) {
            esiaLoginProvider = new ESIALoginProvider();
            esiaLoginProvider.setType("esia");
            esiaLoginProvider.setConnectionUrl("esia");
            esiaLoginProvider.setupLogger(false);
        }

        SecureRandom r = new SecureRandom();
        String authid = String.format("%016x", r.nextLong()) + String.format("%016x", r.nextLong());


        authsessions.put(authid, new AuthSession(login, null, esiaLoginProvider, authid, userInfo, null, null));

        appsessions.put(sesid, authid);

    }

    public void setSettings(String token, String lockoutTime, String loginAttemptsAllowed) throws EAuthServerLogic {

        if (isNull(settingsToken) || (!settingsToken.equals(token))) {
            throw EAuthServerLogic.create("Permission denied.");
        }

        try {

            String sFile;
            try (FileInputStream fin = new FileInputStream(configPath)) {
                sFile = TextUtils.streamToString(fin);
            }
            if (isNull(sFile)) {
                throw EAuthServerLogic.create("Error reading config.xml.");
            }


            if (nonNull(lockoutTime)) {
                int pos1 = sFile.indexOf("<lockouttime>");
                if (pos1 == -1) {
                    throw EAuthServerLogic.create("config.xml does not contain &lt;lockouttime&gt; tag.");
                }

                int pos2 = sFile.indexOf("</lockouttime>");

                String s = sFile.substring(pos1, pos2);

                sFile = sFile.replace(s, "<lockouttime>" + lockoutTime);

                LockoutManager.setLockoutTime(Integer.parseInt(lockoutTime));
            }

            if (nonNull(loginAttemptsAllowed)) {
                int pos1 = sFile.indexOf("<loginattemptsallowed>");
                if (pos1 == -1) {
                    throw EAuthServerLogic.create("config.xml does not contain &lt;loginattemptsallowed&gt; tag.");
                }

                int pos2 = sFile.indexOf("</loginattemptsallowed>");

                String s = sFile.substring(pos1, pos2);

                sFile = sFile.replace(s, "<loginattemptsallowed>" + loginAttemptsAllowed);

                LockoutManager.setLoginAttemptsAllowed(Integer.parseInt(loginAttemptsAllowed));
            }


            try (FileOutputStream fout = new FileOutputStream(configPath)) {
                fout.write(sFile.getBytes(StandardCharsets.UTF_8));
            }

        } catch (Exception e) {
            throw EAuthServerLogic.create(e);
        }
    }


    public void setState(String sesid, String state) {
        String authid = appsessions.get(sesid);
        if (isNull(authid)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid + "__1"));
        }

        AuthSession as = authsessions.get(authid);
        if (isNull(as)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid + "__2"));
        }

        statesessions.put(sesid, state);
    }

    public String getState(String sesid) {
        String authid = appsessions.get(sesid);
        if (isNull(authid)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid + "__1"));
        }

        AuthSession as = authsessions.get(authid);
        if (isNull(as)) {
            throw EAuthServerLogic.create(String.format(SESID_NOT_AUTH, sesid + "__2"));
        }

        return statesessions.get(sesid);
    }


    /**
     * Аутентифицированная сессия. Содержит закэшированный (в оперативной
     * памяти) логин/пароль (для доступа к контексту LDAP, при необходимости) и
     * ссылку на конфигурацию LDAP-сервера
     */
    private static final class AuthSession {
        private final AbstractLoginProvider config;
        private final String authid;
        private final String ip;
        private final String djangoauthid;
        private String userInfo;
        private String name;
        private String pwd;
        private long lastAuthenticated = System.currentTimeMillis();

        public AuthSession(String name, String pwd, AbstractLoginProvider config, final String authid, final String userInfo, final String ip, final String djangoauthid) {
            this.name = name;
            this.pwd = pwd;
            this.config = config;
            this.authid = authid;
            this.userInfo = userInfo;
            this.ip = ip;
            this.djangoauthid = djangoauthid;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPwd() {
            return pwd;
        }

        public void setPwd(String pwd) {
            this.pwd = pwd;
        }

        public String getUserInfo() {
            return userInfo;
        }

        public void setUserInfo(String userInfo) {
            this.userInfo = userInfo;
        }

        public String getIp() {
            return ip;
        }
    }

    /**
     * Разборщик конфигурационного файла.
     */
    private class ConfigParser extends DefaultHandler {
        private static final String CONFIG_NAMESPACE = "http://www.curs.ru/authserver";

        private static final String ATTR_INITIAL_CAPACITY = "initialCapacity";
        private static final String ATTR_LOAD_FACTOR = "loadFactor";
        private static final String ATTR_CONCURRENCY_LEVEL = "concurrencyLevel";
        private final HashMap<String, ParserAction> actions = new HashMap<>();
        private ParserAction currentAction;

        {
            actions.put("sqlserver", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    loginProviders.add(new SQLLoginProvider());
                    loginProviders.getLast().setType("sqlserver");
                }
            });
            actions.put("sqlserverext", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    loginProviders.add(new SQLExtLoginProvider());
                    loginProviders.getLast().setType("sqlserverext");
                }
            });
            actions.put("httpserver", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    loginProviders.add(new HTTPLoginProvider());
                    loginProviders.getLast().setType("httpserver");
                }
            });
            actions.put("iasbpserver", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    loginProviders.add(new IASBPLoginProvider());
                    loginProviders.getLast().setType("iasbpserver");
                }
            });
            actions.put("xmlfile", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    loginProviders.add(new XMLLoginProvider());
                    loginProviders.getLast().setType("xmlfile");
                }
            });
            actions.put("ldapserver", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    loginProviders.add(new LDAPLoginProvider());
                    loginProviders.getLast().setType("ldapserver");
                }
            });

            actions.put("id", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) loginProviders.getLast().setId(value);
                }
            });
            actions.put("logging", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) (loginProviders.getLast()).setupLogger(Boolean.parseBoolean(value));
                }
            });
            actions.put("servertype", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setServertype(
                                LDAPLoginProvider.ServerType.valueOf(value.trim()));
                }
            });
            actions.put("url", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) loginProviders.getLast().setConnectionUrl(value);
                }
            });


            actions.put("hikariproperties", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    for (int i = 0; i < attributes.getLength(); i++) {
                        if (!("".equals(attributes.getValue(i).trim()))) {
                            if (loginProviders.getLast() instanceof SQLLoginProvider) {
                                ((SQLLoginProvider) loginProviders.getLast()).addHikariProperty(
                                        attributes.getQName(i).trim(), attributes.getValue(i).trim());
                            } else {
                                ((SQLExtLoginProvider) loginProviders.getLast()).addHikariProperty(
                                        attributes.getQName(i).trim(), attributes.getValue(i).trim());
                            }
                        }
                    }
                }
            });
            actions.put("connectionusername", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) {
                        if (loginProviders.getLast() instanceof SQLLoginProvider) {
                            ((SQLLoginProvider) loginProviders.getLast()).setConnectionUsername(value);
                        } else {
                            ((SQLExtLoginProvider) loginProviders.getLast()).setConnectionUsername(value);
                        }
                    }
                }
            });
            actions.put("connectionpassword", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) {
                        if (loginProviders.getLast() instanceof SQLLoginProvider) {
                            ((SQLLoginProvider) loginProviders.getLast()).setConnectionPassword(value);
                        } else {
                            ((SQLExtLoginProvider) loginProviders.getLast()).setConnectionPassword(value);
                        }
                    }
                }
            });
            actions.put("table", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) {
                        if (loginProviders.getLast() instanceof SQLLoginProvider) {
                            ((SQLLoginProvider) loginProviders.getLast()).setTable(value);
                        } else {
                            ((SQLExtLoginProvider) loginProviders.getLast()).setTable(value);
                        }
                    }
                }
            });
            actions.put("tableattr", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) ((SQLExtLoginProvider) loginProviders.getLast()).setTableAttr(value);
                }
            });
            actions.put("fieldlogin", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) ((SQLLoginProvider) loginProviders.getLast()).setFieldLogin(value);
                }
            });
            actions.put("fieldpassword", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((SQLLoginProvider) loginProviders.getLast()).setFieldPassword(value);
                }
            });
            actions.put("fieldblocked", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) ((SQLLoginProvider) loginProviders.getLast()).setFieldBlocked(value);
                }
            });
            actions.put("hashalgorithm", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.getLast() instanceof SQLLoginProvider) {
                        ((SQLLoginProvider) loginProviders.getLast()).setHashAlgorithm(value);
                    } else {
                        ((SQLExtLoginProvider) loginProviders.getLast()).setHashAlgorithm(value);
                    }
                }
            });
            actions.put("localsecuritysalt", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.getLast() instanceof SQLLoginProvider) {
                        ((SQLLoginProvider) loginProviders.getLast()).setLocalSecuritySalt(value);
                    } else {
                        ((SQLExtLoginProvider) loginProviders.getLast()).setLocalSecuritySalt(value);
                    }
                }
            });
            actions.put("sidhashalgorithm", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setSidHashAlgorithm(value);
                }
            });
            actions.put("sidlocalsecuritysalt", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setSidLocalSecuritySalt(value);
                }
            });
            actions.put("trusteduser", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) {
                        if (isNull(loginProviders.getLast().getTrustedUsers())) {
                            loginProviders.getLast().setTrustedUsers(new ArrayList<>());
                        }
                        loginProviders.getLast().getTrustedUsers().add(value);
                    }
                }
            });
            actions.put("procpostprocess", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) {
                        if (value.isEmpty()) {
                            value = null;
                        }

                        if (loginProviders.getLast() instanceof SQLLoginProvider) {
                            ((SQLLoginProvider) loginProviders.getLast()).setProcPostProcess(value);
                            procPostProcessProvider = (SQLLoginProvider) loginProviders.getLast();
                        } else {
                            ((SQLExtLoginProvider) loginProviders.getLast()).setProcPostProcess(value);
                            procPostProcessExtProvider = (SQLExtLoginProvider) loginProviders.getLast();
                        }

                    }
                }
            });

            actions.put("validateuser", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((HTTPLoginProvider) loginProviders.getLast()).setValidateUser(value);
                }
            });
            actions.put("userinfobyname", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((HTTPLoginProvider) loginProviders.getLast()).setUserInfoByName(value);
                }
            });
            actions.put("userinfobyid", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((HTTPLoginProvider) loginProviders.getLast()).setUserInfoById(value);
                }
            });
            actions.put("usessl", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setUsessl(Boolean.parseBoolean(value));
                }
            });
            actions.put("sat", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setSat(
                                LDAPLoginProvider.SecurityAuthenticationType.valueOf(value));

                }
            });

            actions.put("domain_name", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) ((LDAPLoginProvider) loginProviders.getLast()).setDomainName(value);
                }
            });

            actions.put("group_providers", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) loginProviders.getLast().setGroupProviders(value);
                }
            });

            actions.put("searchbase", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0) ((LDAPLoginProvider) loginProviders.getLast()).addSearchBase(value);
                }
            });
            actions.put("searchreturningattributes", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    for (int i = 0; i < attributes.getLength(); i++) {
                        if (!("".equals(attributes.getValue(i).trim()))) {
                            (loginProviders.getLast()).addReturningAttributes(attributes.getQName(i).trim(),
                                    attributes.getValue(i).trim());
                        }
                    }
                }
            });
            actions.put("searchfilterforuser", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setSearchFilterForUser(value.trim());
                }
            });
            actions.put("searchfilterforimport", new ParserAction() {
                @Override
                void characters(String value) {
                    if (loginProviders.size() > 0)
                        ((LDAPLoginProvider) loginProviders.getLast()).setSearchFilterForImport(value.trim());
                }
            });

            actions.put("authsessions", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    String value = attributes.getValue(ATTR_INITIAL_CAPACITY);
                    if (nonNull(value)) {
                        authsessionsInitialCapacity = Integer.parseInt(value);
                    }
                    value = attributes.getValue(ATTR_LOAD_FACTOR);
                    if (nonNull(value)) {
                        authsessionsLoadFactor = Integer.parseInt(value) / (float) 100;
                    }
                    value = attributes.getValue(ATTR_CONCURRENCY_LEVEL);
                    if (nonNull(value)) {
                        authsessionsConcurrencyLevel = Integer.parseInt(value);
                    }
                }
            });
            actions.put("appsessions", new ParserAction() {
                @Override
                void startElement(Attributes attributes) {
                    String value = attributes.getValue(ATTR_INITIAL_CAPACITY);
                    if (nonNull(value)) {
                        appsessionsInitialCapacity = Integer.parseInt(value);
                    }
                    value = attributes.getValue(ATTR_LOAD_FACTOR);
                    if (nonNull(value)) {
                        appsessionsLoadFactor = Integer.parseInt(value) / (float) 100;
                    }
                    value = attributes.getValue(ATTR_CONCURRENCY_LEVEL);
                    if (nonNull(value)) {
                        appsessionsConcurrencyLevel = Integer.parseInt(value);
                    }
                }
            });

            actions.put("threadcount", new ParserAction() {
                @Override
                void characters(String value) {
                    if (nonNull(value)) {
                        threadCount = Integer.parseInt(value);
                    }
                }
            });

            actions.put("sessiontimeout", new ParserAction() {
                @Override
                void characters(String value) {
                    if (nonNull(value)) {
                        sessionTimeout = Integer.parseInt(value);
                    }
                }
            });

            actions.put("lockouttime", new ParserAction() {
                @Override
                void characters(String value) {
                    if (nonNull(value)) {
                        LockoutManager.setLockoutTime(Integer.parseInt(value));
                    }
                }
            });

            actions.put("loginattemptsallowed", new ParserAction() {
                @Override
                void characters(String value) {
                    if (nonNull(value)) {
                        LockoutManager.setLoginAttemptsAllowed(Integer.parseInt(value));
                    }
                }
            });

            actions.put("setsettingstoken", new ParserAction() {
                @Override
                void characters(String value) {
                    settingsToken = value;
                }
            });

            actions.put("getuserlisttoken", new ParserAction() {
                @Override
                void characters(String value) {
                    getuserlistToken = value;
                }
            });

            actions.put("showtimetounlockuser", new ParserAction() {
                @Override
                void characters(String value) {
                    if (nonNull(value)) {
                        showTimeToUnlockUser = Boolean.parseBoolean(value);
                    }
                }
            });

            actions.put("checkpasswordhashonly", new ParserAction() {
                @Override
                void characters(String value) {
                    if (nonNull(value)) {
                        checkPasswordHashOnly = Boolean.parseBoolean(value);
                    }
                }
            });

        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            if (CONFIG_NAMESPACE.equals(uri)) {
                currentAction = actions.get(localName);
                if (nonNull(currentAction)) currentAction.startElement(attributes);
            } else {
                currentAction = null;
            }
        }

        @Override
        public void characters(char[] ch, int start, int length) {
            if (nonNull(currentAction)) {
                currentAction.characters((new String(ch, start, length)).trim());
                currentAction = null;
            }
        }

        /**
         * Обработчик события "тэг конфигурационного файла".
         */
        private abstract class ParserAction {

            void startElement(Attributes attributes) {
            }

            void characters(String value) {
            }

        }

    }


}
