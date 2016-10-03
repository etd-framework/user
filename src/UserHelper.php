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

use Joomla\Crypt\Crypt;
use Joomla\Database\DatabaseDriver;

class UserHelper {

    /**
     * @var Acl
     */
    private $acl;

    /**
     * @var DatabaseDriver Le moteur de base de données.
     */
    private $db;

    function __construct($db) {

        $this->db  = $db;
        $this->acl = Acl::getInstance($db);

    }

    /**
     * Retourne les groupes utilisateurs.
     *
     * @return array Un tableau des groupes utilisateurs.
     */
    public function getUserGroups() {

        $db = $this->db;

        $query = $db->getQuery(true)
                    ->select('a.*, COUNT(DISTINCT b.id) AS level')
                    ->from($db->quoteName('#__usergroups') . ' AS a')
                    ->join('LEFT', $db->quoteName('#__usergroups') . ' AS b ON a.lft > b.lft AND a.rgt < b.rgt')
                    ->group('a.id, a.title, a.lft, a.rgt, a.parent_id')
                    ->order('a.lft ASC');

        return $db->setQuery($query)
                  ->loadObjectList();

    }

    /**
     * Retour les groupes auxquels appartient un utilisateur.
     *
     * @param int $id L'identifiant de l'utilisateur.
     *
     * @return array Un tableau d'idenfitiant des groupes auxquels appartient l'utilisateur.
     */
    public function getGroupsByUser($id) {

        return $this->acl->getGroupsByUser($id);

    }

    /**
     * Génère un mot de passe aléatoire.
     *
     * @param   integer $length Longueur du mot de passe à générer.
     *
     * @return  string  Le mot de passe aléatoire.
     */
    public function genRandomPassword($length = 8) {

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

    /**
     * Retourne une chaine crypté du mot de passe.
     *
     * @param   string  $password  Le mot de passe à cryper.
     * @param   integer $algo      L'algorithme à utiliser.
     * @param   array   $options   Un tableau associatif contenant les options.
     *
     * @return  string  Le mot de passe crypté.
     */
    public function cryptPassword($password, $algo = PASSWORD_BCRYPT, $options = null) {

        return password_hash($password, $algo, $options);

    }

    /**
     * Méthode pour contrôler un mot de passe par rapport à un hash.
     *
     * @param string $password Le mot de passe en clair à vérifier.
     * @param string $hash     Le hash contre lequel le mot de passe est vérifié.
     *
     * @return bool True si identique, false sinon.
     */
    public function verifyPassword($password, $hash) {

        return password_verify($password, $hash);

    }

}