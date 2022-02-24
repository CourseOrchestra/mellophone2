package ru.curs.mellophone.logic;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Тесты XMLLoginProvider.
 */
public class XMLLoginProviderTest extends BaseTestLoginProvider {

    private static final String LOGIN = "Петров";
    private static final String PASSWORD = "пасс2";
    private static final String BAD_PASSWORD = "пасс22";

    private static final String CHECKNAME_EXISTS = "Сидоров";
    private static final String CHECKNAME_NOT_EXISTS = "Сидоров22";


    /**
     * Тест успешной загрузки XMLLoginProvider'а.
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testXMLLoginProviderIsLoaded() throws EAuthServerLogic {
        int count = 0;
        for (int i = 0; i < AuthManager.getTheManager().getLoginProviders().size(); i++) {
            if (AuthManager.getTheManager().getLoginProviders().get(0) instanceof XMLLoginProvider) {
                count++;
            }
        }
        assertEquals(1, count);
    }


    /**
     * Тест ф-ции login (успешный логин).
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testLogin1() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);

        login();
    }


    /**
     * Тест ф-ции login (неуспешный логин).
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testLogin2() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(BAD_PASSWORD);

        try {
            login();
        } catch (EAuthServerLogic e) {
            assertTrue(e.getMessage().indexOf("Неправильная пара логин/пароль") > 0);
        }
    }


    /**
     * Тест1 ф-ции isAuthenticated (аутентифицированная сессия).
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testIsAuthenticated1() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);

        isAuthenticated1();
    }

    /**
     * Тест2 ф-ции isAuthenticated (не аутентифицированная сессия).
     */
    @Test
    public void testIsAuthenticated2() {
        isAuthenticated2();
    }

    /**
     * Тест ф-ции logout.
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testLogout() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);

        logout();
    }

    /**
     * Тест1 ф-ции checkName (имя пользователя существует).
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testCheckName1() throws EAuthServerLogic {


        setLogin(LOGIN);
        setPassword(PASSWORD);
        setCheckname(CHECKNAME_EXISTS);

        checkName1();
    }

    /**
     * Тест2 ф-ции checkName (имя пользователя не существует).
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testCheckName2() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);
        setCheckname(CHECKNAME_NOT_EXISTS);

        checkName2();
    }

    /**
     * Тест1 ф-ции authenticationGif.
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testAuthenticationGif1() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);

        authenticationGif1();
    }

    /**
     * Тест2 ф-ции authenticationGif.
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testAuthenticationGif2() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);

        authenticationGif2();
    }

    /**
     * Тест3 ф-ции authenticationGif.
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
    @Test
    public void testAuthenticationGif3() throws EAuthServerLogic {
        authenticationGif3();
    }

    /**
     * Тест ф-ции importUsers.
     *
     * @throws EAuthServerLogic EAuthServerLogic
     */
/*
    @Test
    public void testImportUsers() throws EAuthServerLogic {
        setLogin(LOGIN);
        setPassword(PASSWORD);

        importUsers();
    }
*/

}
