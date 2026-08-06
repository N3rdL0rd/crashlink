enum Kind {
    A;
    B(child:Kind);
}

class EnumDestruct {
    static function main() {
        var e = B(A);
        switch (e) {
            case B(A):
                Sys.println("ba");
            case _:
                Sys.println("other");
        }
    }
}
