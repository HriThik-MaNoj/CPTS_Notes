#### Installation
```python
sudo apt install bloodhound
sudo bloodhound-setup

username & passwd for neo4j : neo4j
# run bloodhound
sudo bloodhound
```

#### Choosing injesters
- If you have a set of domain credentials but no foothold on a widows domain joined system, then we can run the **bloodhound-python** injester straight from our linux box.
```python
sudo bloodhound-python -u 'olivia' -p 'ichiliebedich' -ns 10.10.11.42 -d administrator.htb -c all
```
###### RustHound
- Alternative to bloodhound-python, more feature rich and is platform independent.
```python
sudo rusthound -u 'olivia' -p 'ichiliebedich' -f 10.10.11.42 -d administrator.htb
```

#### Sharphound
- written in C#
- [releases page](https://github.com/SpecterOps/SharpHound/releases)

  