class Config {
    public static var base:Int = 100;
    public static var derived:Int = base * 2;
}

class StaticInitOrder {
    static function main() {
        Sys.println(Config.base);
        Sys.println(Config.derived);
    }
}
