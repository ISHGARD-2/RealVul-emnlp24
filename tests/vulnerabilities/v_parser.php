<?php
class a{
    function a(){
        while(1==1){
            if(1==1){
                function b(){
                    $test = null;
                     //print($taint);
                     if($test){
                        $taint = $_GET['test'];
                     }
                     else{
                        echo system(trim('ls'.$taint));
                     }
                }
             }
        }
    }
}

function c($taint){
    $test = null;
    $taint_start = $_GET['test'];
    $taint = $taint_start + $test;
     //print($taint);
     if($test){
        echo system(trim('ls'.$taint));
     }
}
?>