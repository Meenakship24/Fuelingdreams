import { Component, OnInit } from '@angular/core'; // Added OnInit
import { HttpClient, HttpClientModule } from '@angular/common/http'; // Added HttpClient import
import { SideNavComponent } from "../side-nav/side-nav.component";
import { ProfileService } from '../profile.service';
import { CommonModule } from '@angular/common';
import { MatIcon, MatIconModule } from '@angular/material/icon';
import { CropperDialoComponent } from '../UPP/cropper-dialo/cropper-dialo.component';
import { ImageContComponent } from '../UPP/image-cont/image-cont.component';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [SideNavComponent ,HttpClientModule , CommonModule, MatIconModule, CropperDialoComponent, ImageContComponent],
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss'], // Corrected `styleUrl` to `styleUrls`
  providers:[ProfileService]
})
export class ProfileComponent implements OnInit {

  profileData: any = {};

  constructor(private http: HttpClient) { }

  ngOnInit(): void {
    this.fetchProfileData();
  }

  fetchProfileData(): void {
    // Replace 'your-api-endpoint' with the actual API endpoint to fetch profile data
    const apiEndpoint = 'http://localhost:5000/api/profile'; // Example endpoint

    this.http.get(apiEndpoint).subscribe(
      (data: any) => {
        this.profileData = data;
      },
      (error) => {
        console.error('Error fetching profile data:', error);
      }
    );
  }

  imageReady(blob:Blob){
    console.log(blob);
  }
}
