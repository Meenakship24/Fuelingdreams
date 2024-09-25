// import { Injectable } from '@angular/core';
// import { HttpClient } from '@angular/common/http';
// import { Observable } from 'rxjs';

// @Injectable()
// export class ProfileService {
//   private apiUrl = 'http://localhost:3000/api/profile';

//   constructor(private http: HttpClient) {}

//   getUserProfile(userId: number): Observable<any> {
//     return this.http.get(`${this.apiUrl}/${userId}`);
//   }

//   uploadProfilePicture(formData: FormData): Observable<any> {
//     return this.http.post('http://localhost:3000/api/uploadProfilePicture', formData);
//   }
// }

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ProfileService {

  private apiUrl = 'http://localhost:5000/api/profile';

  constructor(private http: HttpClient) { }

  getUserProfile(userId: number): Observable<any> {
    return this.http.get(`${this.apiUrl}/${userId}`);
  }
}

