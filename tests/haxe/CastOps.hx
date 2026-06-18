class CastOps {
    static function main() {
        var d:Dynamic = 42;
        var s:String = cast(getDynamic(), String);
        var i:Int = cast d;
        trace(s);
        trace(i);
    }

    static function getDynamic():Dynamic {
        return "hello";
    }
}
