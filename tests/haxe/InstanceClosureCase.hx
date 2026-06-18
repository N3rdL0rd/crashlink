class InstClosureObj {
    public function new() {}

    public function greet(name:String):String {
        return "hi " + name;
    }
}

class InstanceClosureCase {
    public static function main() {
        var obj = new InstClosureObj();
        var f = obj.greet;
        trace(f("world"));
    }
}
