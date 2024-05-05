<?php



namespace Solenoid\IDK;



use \Solenoid\Encryption\AES;
use \Solenoid\Base64U\Base64U;



class IDK
{
    public string $user;
    public string $key;

    public array  $data;



    # Returns [self]
    public function __construct (string $user, string $key, array $data = [])
    {
        // (Getting the values)
        $this->user = $user;
        $this->key  = $key;

        $this->data = $data;
    }

    # Returns [IDK]
    public static function create (string $user, string $key, array $data = [])
    {
        // Returning the value
        return new IDK( $user, $key, $data );
    }



    # Returns [string|false] | Throws [Exception]
    public function build (?string $passphrase = null, bool $url_encode = false)
    {
        // (Getting the value)
        $value =
            json_encode
            (
                [
                    'user' => $this->user,
                    'key'  => $this->key,

                    'data' => $this->data
                ]
            )
        ;



        if ( $passphrase )
        {// Value found
            // (Getting the value)
            $value = AES::select( $value )->encrypt( $passphrase );

            if ( $value === false )
            {// (Unable to encrypt the value)
                // (Setting the value)
                $message = "Unable to encrypt the value";

                // Throwing an exception
                throw new \Exception($message);

                // Returning the value
                return false;
            }



            // (Getting the value)
            $value = (string) $value;
        }



        if ( $url_encode )
        {// Value is true
            // (Getting the value)
            $value = Base64U::select( $value )->encode()->value;
        }



        // Returning the value
        return $value;
    }

    # Returns [IDK|false]
    public static function read (string $idk, ?string $passphrase = null, bool $url_decode = false)
    {
        // (Getting the value)
        $value = $idk;



        if ( $url_decode )
        {// Value is true
            // (Getting the value)
            $value = Base64U::select( $value )->decode()->value;
        }



        if ( $passphrase )
        {// Value found
            // (Getting the value)
            $value = AES::select( $value )->decrypt( $passphrase );

            if ( $value === false )
            {// (Key is not valid)
                // Returning the value
                return false;
            }



            // (Getting the value)
            $value = (string) $value;
        }



        // (Getting the value)
        $entries = json_decode( $value, true );



        // Returning the value
        return
            IDK::create( $entries['user'], $entries['key'], $entries['data'] )
        ;
    }



    # Returns [string]
    public function __toString ()
    {
        // Returning the value
        return $this->build();
    }
}



?>