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
use EtdSolutions\Language\LanguageFactory;
use EtdSolutions\Table\UserTable;

use Joomla\Crypt\Crypt;
use Joomla\Data\DataObject;
use Joomla\DI\Container;
use Joomla\DI\ContainerAwareInterface;
use Joomla\DI\ContainerAwareTrait;
use Joomla\Registry\Registry;
use Joomla\Utilities\ArrayHelper;

/**
 * Class User
 *
 * @package EtdSolutions\User
 *
 * @property integer  $id     L'identifiant de l'utilisateur.
 * @property bool     $guest  True si l'utilisateur n'est pas connecté.
 * @property Registry $params Un registre contenant les paramètres personnalisés de l'utilisateur.
 */
class User extends DataObject implements ContainerAwareInterface {

    use ContainerAwareTrait;

    /**
     * @var array Un tableau pour mettre en cache les propriétés des instances.
     */
    private static $instances = [];

    /**
     * Constructeur.
     *
     * @param Container $container
     */
    public function __construct(Container $container) {

        $this->setContainer($container);

        parent::__construct([
            'id'        => 0,
            'sendEmail' => 0,
            'guest'     => 1,
            'params'    => new Registry,
            'profile'   => new \stdClass()
        ]);

    }

    /**
     * Détermine si l'utilisateur est invité
     *
     * @return bool True si invité, false sinon.
     */
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

        $container = $this->getContainer();
        $acl       = Acl::getInstance($container->get('db'));
        $user_id   = (int)$this->getProperty('id');

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
        $container = $this->getContainer();
        $table     = new UserTable($container->get('db'));

        // On met à jour la date.
        return $table->setLastVisit($timestamp, $this->getProperty('id'));
    }

    /**
     * Méthode pour charger les données d'un utilisateur.
     *
     * @param   int  $id    L'id de l'utilisateur.
     * @param   bool $force True pour forcer le rechargement.
     *
     * @return  User
     *
     * @throws  \RuntimeException
     */
    public function load($id = null, $force = false) {

        $container = $this->getContainer();

        // On s'assure d'avoir un integer.
        $id = (int)$id;

        // Si aucun id n'est passé, on tente de le trouvé dans la session.
        if (empty($id)) {

            $id = (int)$container->get('session')->get('user_id');

            // Si c'est toujours vide, on retourne l'utilisateur courant.
            if (empty($id)) {
                $this->clear();

                return $this;
            }

        }

        // On regarde si l'utilisateur n'est pas déjà en cache.
        if (!isset(self::$instances[$id]) || $force) {

            $text = (new LanguageFactory)->getText();

            // On récupère le table.
            $table = new UserTable($container->get('db'));

            // On tente de charger l'utilisateur.
            if (!$table->load($id)) {

                // On déclenche une exception.
                throw new \RuntimeException($text->sprintf('USER_ERROR_UNABLE_TO_LOAD_USER', $id));

            } else {

                // On récupère ses propriétés.
                $user = $table->dump();

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

            $instance = new User($container);
            $instance->bind($user);

            self::$instances[$id] = $instance;

        }

        return self::$instances[$id];
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

    protected function clear() {

        $this->bind([
            'id'        => 0,
            'sendEmail' => 0,
            'guest'     => 1,
            'params'    => new Registry,
            'profile'   => new \stdClass()
        ]);

    }

}