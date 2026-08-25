enum Kind {
    Node(value:Int, next:Kind);
    End;
}

class RecursiveEnumChain {
    static function sum(k:Kind):Int {
        return switch (k) {
            case Node(v, next): v + sum(next);
            case End: 0;
        }
    }

    static function main() {
        var chain = Node(1, Node(2, Node(3, End)));
        Sys.println(sum(chain));
        switch (chain) {
            case Node(v, Node(v2, _)):
                Sys.println('first=$v second=$v2');
            default:
                Sys.println("no-match");
        }
    }
}
