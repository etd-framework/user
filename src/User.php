<?php
/**
 * Part of the ETD Framework User Package
 *
 * @copyright   Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     Apache License 2.0; see LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\User;

use EtdSolutions\Acl\Acl;
use EtdSolutions\Application\Web;
use EtdSolutions\Table\Table;
use Joomla\Crypt\Crypt;
use Joomla\Data\DataObject;
use Joomla\Filter\InputFilter;
use Joomla\Registry\Registry;
use Joomla\Utilities\ArrayHelper;

defined('_JEXEC') or die;

/**
 * Class User
 *
 * @package EtdSolutions\User
 *
 * @property integer  $id     L'identifiant de l'utilisateur.
 * @property bool     $guest  True si l'utilisateur n'est pas connecté.
 * @property Registry $params Un registre contenant les paramètres personnalisés de l'utilisateur.
 */
class User extends DataObject {

    /**
     * @var    array  Instances User.
     */
    protected static $instances = array();

    /**
     * Instancie l'objet utilisateur.
     *
     * @param   integer $id La clé primaire identifiant l'utilisateur à charger.
     */
    public function __construct($id = 0) {

        // On charge l'utilisateur s'il existe.
        if (!empty($id)) {
            $properties = $this->load($id);
        } else {
            // Initialise
            $properties = array(
                'id'        => 0,
                'sendEmail' => 0,
                'guest'     => 1,
                'params'    => new Registry,
                'profile'   => new \stdClass()
            );
        }

        parent::__construct($properties);
    }

    /**
     * Retourne l'objet global User, en le créant seulement il n'existe pas déjà.
     *
     * @param   integer $id L'utilisateur à charger
     *
     * @return  User  L'objet User.
     */
    public static function getInstance($id = null) {

        $app      = Web::getInstance();
        $instance = $app->getSession()
                        ->get('user');

        if (is_null($id) || (!is_null($instance) && $instance->id == $id)) {

            if (!($instance instanceof User)) {
                return new User;
            }

            return $instance;
        } elseif (is_null($instance) || $instance->id != $id) {

            // On regarde si cet utilisateur est déjà en cache.
            if (empty(self::$instances[$id])) {
                self::$instances[$id] = new User($id);
            }

        }

        return self::$instances[$id];
    }

    public function isGuest() {

        $guest = $this->getProperty('guest');

        return ($guest == 1 || $guest === null);
    }

    /**
     * Méthode pour contrôler si l'utilisateur a le droit d'effectuer une action.
     *
     * @param   string $section La section sur laquelle on veut appliquer l'action.
     * @param   string $action  Le nom de l'action a contrôler.
     *
     * @return  boolean  True si autorisé, false sinon.
     */
    public function authorise($section, $action = '') {

        $acl     = Acl::getInstance();
        $user_id = (int) $this->getProperty('id');

        // Raccourci
        if (strpos($section, '.') !== false) {
            list($section, $action) = explode(".", $section, 2);
        }

        return $acl->checkUser($user_id, $section, $action);

    }

    /**
     * Méthode proxy pour le modèle pour mettre à jour la date de visite.
     *
     * @param   integer $timestamp The timestamp, defaults to 'now'.
     *
     * @return  boolean  True en cas de succès.
     */
    public function setLastVisit($timestamp = null) {

        // On récupère le table.
        $table = Table::getInstance('user');

        // On met à jour la date.
        return $table->setLastVisit($timestamp, $this->getProperty('id'));
    }

    /**
     * Méthode proxy pour le modèle pour charger un utilisateur.
     *
     * @param   mixed $id The user id of the user to load
     *
     * @return  object  Les données de l'utilisteur.
     *
     * @throws  \RuntimeException
     */
    public function load($id) {

        $text = Web::getInstance()
                   ->getText();

        // On récupère le table.
        $table = Table::getInstance('user');

        // On tente de charger l'utilisateur.
        if (!$table->load($id)) {

            // On déclenche une exception.
            throw new \RuntimeException($text->sprintf('USER_ERROR_UNABLE_TO_LOAD_USER', $id));

        } else {

            // On récupère ses propriétés.
            $user = $table->dump(0);

            // Ce n'est plus un invité.
            $user->guest = 0;

            // On transforme les paramètres en registre.
            $user->params = new Registry($user->params);

            // On transforme le profile en objet.
            if (is_array($user->profile)) {
                $user->profile = ArrayHelper::toObject($user->profile);
            }

            // On vire le mot de passe.
            $user->password = '';

        }

        return $user;
    }

    /**
     * Méthode pour déconnecter l'utilisateur.
     *
     * @return bool True si succès.
     */
    public function logout() {

        $my      = self::getInstance();
        $app     = Web::getInstance();
        $session = $app->getSession();
        $db      = $app->getDb();
        $input   = $app->getInput();

        // Est-on en train de supprimer la session en cours ?
        if ($my->id == $this->id) {

            // On met à jour la dernière visite.
            $this->setLastVisit();

            // On supprime la session PHP.
            $session->destroy();
        }

        // On force la déconnexion de tous les utilisateurs avec cet id.
        $db->setQuery($db->getQuery(true)
                         ->delete($db->quoteName('#__session'))
                         ->where($db->quoteName('userid') . ' = ' . (int)$this->id))
           ->execute();

        // On supprime tous les cookie d'authentification de l'utilisateur.
        $cookieName  = $app->getShortHashedUserAgent();
        $cookieValue = $input->cookie->get($cookieName);

        // S'il n y a de cookie à supprimer.
        if (!$cookieValue) {
            return true;
        }

        $cookieArray = explode('.', $cookieValue);

        // On filtre la série car on l'utilise dans la requête.
        $filter = new InputFilter;
        $series = $filter->clean($cookieArray[1], 'ALNUM');

        // On supprime l'enregistrement dans la base de données.
        $query = $db->getQuery(true);
        $query->delete('#__user_keys')
              ->where($db->quoteName('series') . ' = ' . $db->quote($series));
        $db->setQuery($query)
           ->execute();

        // On supprime le cookie.
        $input->cookie->set($cookieName, false, time() - 42000, $app->get('cookie_path', '/'), $app->get('cookie_domain'));

        return true;

    }

    /**
     * Génère un mot de passe aléatoire.
     *
     * @param   integer $length Longueur du mot de passe à générer.
     *
     * @return  string  Le mot de passe aléatoire.
     */
    public static function genRandomPassword($length = 8) {

        $salt     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $base     = strlen($salt);
        $makepass = '';

        /*
         * Start with a cryptographic strength random string, then convert it to
         * a string with the numeric base of the salt.
         * Shift the base conversion on each character so the character
         * distribution is even, and randomize the start shift so it's not
         * predictable.
         */
        $random = Crypt::genRandomBytes($length + 1);
        $shift  = ord($random[0]);

        for ($i = 1; $i <= $length; ++$i) {
            $makepass .= $salt[($shift + ord($random[$i])) % $base];
            $shift += ord($random[$i]);
        }

        return $makepass;
    }

}