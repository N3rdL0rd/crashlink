class Config {
    public static var BASE:Int = 100;
    public static var NAME:String = "cfg";
}

class Widget {
    public var id:Int = Config.BASE + 1;
    public var tag:String = Config.NAME + "-w";
    public function new() {}
}

class InstanceDefaultFromStatic {
    static function main() {
        var w = new Widget();
        Config.BASE = 999;
        var w2 = new Widget();
        trace(w.id);
        trace(w.tag);
        trace(w2.id);
        trace(w2.tag);
    }
}
