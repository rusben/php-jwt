<?php

// General singleton class.

class DatabaseController {

    private static $host = "localhost";
    private static $username = "usuario";
    private static $password = "password";
    private static $dbname = "jwt";
    //private $dsn = 'mysql:host='.$host.';dbname='.$dbname;
    private static $options = array(
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, 
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8"
                  );

    // Hold the class instance.
    private static $instance = null;
    
    // The constructor is private
    // to prevent initiation with outer code.
    private function __construct()
    {
      // The expensive process (e.g.,db connection) goes here.
    }
   
    // The object is created from within the class itself
    // only if the class has no instance.
    public static function getInstance()
    {
      if (self::$instance == null)
      {
        self::$instance = new DatabaseController();
      }
   
      return self::$instance;
    }

    public static function connect () {
        try  {
            $connection = new PDO('mysql:host='.self::$host.';dbname='.self::$dbname, self::$username, self::$password, self::$options);
            return $connection;
   
          } catch(PDOException $error) {
              echo $sql . "<br>" . $error->getMessage();
              return null;
          }
    }
  }