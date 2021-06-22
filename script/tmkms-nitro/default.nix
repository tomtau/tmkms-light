with import <nixpkgs> {};

( let
    cose = pkgs.python39Packages.buildPythonPackage rec {
      pname = "cose";
      version = "0.9.dev7";

      src = pkgs.python39Packages.fetchPypi{
        inherit pname version;  
        sha256 = "d82cb1ebcdc5c759c1307f7302c5e6cb327d4195c03c31cb5fbdf6851a74d7ea";
      };
     doCheck = false;
    preConfigure = ''
    touch requirements.txt
  '';
    };
    attr = pkgs.python39Packages.buildPythonPackage rec {
      pname = "attrs";
      version = "21.2.0";

      src = pkgs.python39Packages.fetchPypi{
        inherit pname version;  
        sha256 = "ef6aaac3ca6cd92904cdd0d83f629a15f18053ec84e6432106f7a4d04ae4f5fb";
      };
     doCheck = false;

    };

  in pkgs.python39.buildEnv.override rec {

    extraLibs = [ pkgs.python39Packages.pycryptodome pkgs.python39Packages.cbor2 cose attr pkgs.python39Packages.cryptography pkgs.python39Packages.ecdsa pkgs.python39Packages.pyopenssl ];
}
).env
