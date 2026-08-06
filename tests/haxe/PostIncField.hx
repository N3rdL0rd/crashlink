class PostIncField {
    var cur:Int;

    function new() {
        cur = 3;
    }

    function take():Int {
        return cur++;
    }

    static function main() {
        var p = new PostIncField();
        Sys.println(p.take());
        Sys.println(p.cur);
    }
}
