class MyExc extends haxe.Exception {
    public function new(m:String) {
        super(m);
    }
}

class ExcSubCatch {
    static function main() {
        try {
            throw "x";
        } catch (e:MyExc) {
            Sys.println("exc");
        }
    }
}
